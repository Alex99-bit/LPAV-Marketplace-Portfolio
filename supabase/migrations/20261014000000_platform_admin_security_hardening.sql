-- Security hardening for platform administration.
-- User metadata and self-service profile updates must never grant privileges.

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  INSERT INTO public.profiles (id, email, full_name, role_name, tenant_id)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'full_name', 'Viajero Anonimo'),
    'EndUser',
    NULL
  );
  RETURN NEW;
END;
$$;

-- Clients can edit profile presentation fields, never identity or authorization.
REVOKE UPDATE ON public.profiles FROM anon, authenticated;
GRANT UPDATE (full_name, avatar_url, phone) ON public.profiles TO authenticated;

CREATE OR REPLACE FUNCTION public.mark_agency_pending()
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_user_id UUID := auth.uid();
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'Usuario no autenticado';
  END IF;

  UPDATE public.profiles
  SET role_name = 'Agency_Pending'
  WHERE id = v_user_id
    AND tenant_id IS NULL
    AND role_name = 'EndUser';

  IF FOUND THEN
    RETURN TRUE;
  END IF;

  RETURN EXISTS (
    SELECT 1
    FROM public.profiles
    WHERE id = v_user_id
      AND tenant_id IS NULL
      AND role_name = 'Agency_Pending'
  );
END;
$$;

REVOKE ALL ON FUNCTION public.mark_agency_pending() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.mark_agency_pending() TO authenticated;

-- Prevent agency invitations from assigning the platform administrator role,
-- including invitations inserted directly through the Data API.
UPDATE public.agency_invitations
SET role_name = 'Agency_Collaborator'
WHERE lower(btrim(role_name)) IN ('superadmin', 'super_admin', 'platform_admin');

CREATE OR REPLACE FUNCTION public.reject_platform_admin_invitation_role()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  IF lower(btrim(NEW.role_name)) IN ('superadmin', 'super_admin', 'platform_admin') THEN
    RAISE EXCEPTION 'No se pueden asignar roles administrativos de plataforma mediante invitaciones';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS reject_platform_admin_invitation_role ON public.agency_invitations;
CREATE TRIGGER reject_platform_admin_invitation_role
  BEFORE INSERT OR UPDATE OF role_name ON public.agency_invitations
  FOR EACH ROW
  EXECUTE FUNCTION public.reject_platform_admin_invitation_role();

-- An agency admin may edit its public/business details but not its approval,
-- billing, ownership, plan, or platform-controlled fields.
CREATE OR REPLACE FUNCTION public.guard_agency_platform_fields()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF auth.role() = 'authenticated'
     AND COALESCE(public.get_current_user_role(), '') <> 'SuperAdmin'
     AND (
       OLD.status IS DISTINCT FROM NEW.status OR
       OLD.subscription_tier IS DISTINCT FROM NEW.subscription_tier OR
       OLD.stripe_account_id IS DISTINCT FROM NEW.stripe_account_id OR
       OLD.stripe_customer_id IS DISTINCT FROM NEW.stripe_customer_id OR
       OLD.stripe_subscription_id IS DISTINCT FROM NEW.stripe_subscription_id OR
       OLD.owner_user_id IS DISTINCT FROM NEW.owner_user_id OR
       OLD.plan_type IS DISTINCT FROM NEW.plan_type OR
       OLD.commission_rate IS DISTINCT FROM NEW.commission_rate OR
       OLD.preferential_rate_active IS DISTINCT FROM NEW.preferential_rate_active OR
       OLD.verification_status IS DISTINCT FROM NEW.verification_status OR
       OLD.fundador_request_status IS DISTINCT FROM NEW.fundador_request_status OR
       OLD.fundador_requested_at IS DISTINCT FROM NEW.fundador_requested_at OR
       OLD.fundador_activated_at IS DISTINCT FROM NEW.fundador_activated_at OR
       OLD.fundador_continuity_pending IS DISTINCT FROM NEW.fundador_continuity_pending OR
       OLD.fundador_continuity_active IS DISTINCT FROM NEW.fundador_continuity_active
     ) THEN
    RAISE EXCEPTION 'Solo la plataforma puede modificar campos de aprobación, plan o facturación';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_agency_platform_fields ON public.agencies_tenants;
CREATE TRIGGER guard_agency_platform_fields
  BEFORE UPDATE ON public.agencies_tenants
  FOR EACH ROW
  EXECUTE FUNCTION public.guard_agency_platform_fields();

-- Platform operations need these reads, but access is granted only by the
-- server-managed role after profile escalation is closed.
DROP POLICY IF EXISTS "SuperAdmin reads all profiles" ON public.profiles;
CREATE POLICY "SuperAdmin reads all profiles" ON public.profiles
  FOR SELECT TO authenticated
  USING (public.get_current_user_role() = 'SuperAdmin');

DROP POLICY IF EXISTS "SuperAdmin reads all travel packages" ON public.travel_packages;
CREATE POLICY "SuperAdmin reads all travel packages" ON public.travel_packages
  FOR SELECT TO authenticated
  USING (public.get_current_user_role() = 'SuperAdmin');

DROP POLICY IF EXISTS "SuperAdmin reads all transactions" ON public.transactions_orders;
CREATE POLICY "SuperAdmin reads all transactions" ON public.transactions_orders
  FOR SELECT TO authenticated
  USING (public.get_current_user_role() = 'SuperAdmin');

DROP POLICY IF EXISTS "SuperAdmin reads all CRM leads" ON public.crm_leads;
CREATE POLICY "SuperAdmin reads all CRM leads" ON public.crm_leads
  FOR SELECT TO authenticated
  USING (public.get_current_user_role() = 'SuperAdmin');

-- close_fiscal_period is an administrative operation, not a public RPC.
CREATE OR REPLACE FUNCTION public.close_fiscal_period(p_period_id UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_start DATE;
  v_end DATE;
  v_inc_sub NUMERIC;
  v_inc_iva NUMERIC;
  v_exp_sub NUMERIC;
  v_exp_iva NUMERIC;
BEGIN
  IF auth.uid() IS NULL OR public.get_current_user_role() <> 'SuperAdmin' THEN
    RAISE EXCEPTION 'Solo el SuperAdmin puede cerrar periodos fiscales';
  END IF;

  SELECT period_start, period_end INTO v_start, v_end
  FROM public.fiscal_periods
  WHERE period_id = p_period_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Periodo no encontrado';
  END IF;

  SELECT income_subtotal, income_iva, expense_subtotal, expense_iva
  INTO v_inc_sub, v_inc_iva, v_exp_sub, v_exp_iva
  FROM public.calculate_period_totals(v_start, v_end);

  UPDATE public.fiscal_periods SET
    total_income_subtotal = v_inc_sub,
    total_income_iva = v_inc_iva,
    total_expense_subtotal = v_exp_sub,
    total_expense_iva = v_exp_iva,
    iva_to_declare = v_inc_iva - v_exp_iva,
    isr_base = v_inc_sub - v_exp_sub,
    status = 'closed',
    closed_at = NOW(),
    closed_by = auth.uid()
  WHERE period_id = p_period_id;

  UPDATE public.fiscal_income_records
  SET fiscal_period_id = p_period_id
  WHERE recorded_at::date BETWEEN v_start AND v_end
    AND fiscal_period_id IS NULL;

  UPDATE public.fiscal_expense_records
  SET fiscal_period_id = p_period_id
  WHERE recorded_at::date BETWEEN v_start AND v_end
    AND fiscal_period_id IS NULL;
END;
$$;

-- The historical blanket function grants made SECURITY DEFINER routines
-- callable by every API role. Default to no client execution and allow only
-- the application RPCs and RLS helper functions explicitly required here.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.get_current_user_tenant() TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_current_user_role() TO authenticated;
GRANT EXECUTE ON FUNCTION public.can_manage_catalog() TO authenticated;
GRANT EXECUTE ON FUNCTION public.can_view_global_leads() TO authenticated;
GRANT EXECUTE ON FUNCTION public.can_manage_finance() TO authenticated;
GRANT EXECUTE ON FUNCTION public.can_manage_chat() TO authenticated;
GRANT EXECUTE ON FUNCTION public.mark_agency_pending() TO authenticated;

GRANT EXECUTE ON FUNCTION public.register_agency(
  VARCHAR, VARCHAR, TEXT, TEXT, VARCHAR, VARCHAR,
  BOOLEAN, BOOLEAN, BOOLEAN, BOOLEAN
) TO authenticated;
GRANT EXECUTE ON FUNCTION public.accept_invitation(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.create_invitation(VARCHAR, VARCHAR) TO authenticated;
GRANT EXECUTE ON FUNCTION public.approve_fundador(UUID, BOOLEAN, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION public.close_fiscal_period(UUID) TO authenticated;

REVOKE ALL ON FUNCTION public.seed_profile(UUID, TEXT, TEXT, TEXT, UUID)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.calculate_period_totals(DATE, DATE)
  FROM PUBLIC, anon, authenticated;
