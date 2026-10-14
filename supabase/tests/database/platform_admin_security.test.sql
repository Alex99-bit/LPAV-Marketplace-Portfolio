BEGIN;

SELECT plan(11);

SELECT ok(
  NOT has_column_privilege('authenticated', 'public.profiles', 'role_name', 'UPDATE'),
  'authenticated users cannot update profile roles'
);

SELECT ok(
  NOT has_column_privilege('authenticated', 'public.profiles', 'tenant_id', 'UPDATE'),
  'authenticated users cannot move profiles between tenants'
);

SELECT ok(
  has_column_privilege('authenticated', 'public.profiles', 'full_name', 'UPDATE'),
  'authenticated users can still update their display name'
);

SELECT ok(
  NOT has_function_privilege(
    'authenticated',
    'public.seed_profile(uuid,text,text,text,uuid)',
    'EXECUTE'
  ),
  'profile seeding RPC is not callable by authenticated users'
);

SELECT ok(
  NOT has_function_privilege(
    'anon',
    'public.seed_profile(uuid,text,text,text,uuid)',
    'EXECUTE'
  ),
  'profile seeding RPC is not callable by anonymous users'
);

SELECT ok(
  NOT has_function_privilege(
    'authenticated',
    'public.calculate_period_totals(date,date)',
    'EXECUTE'
  ),
  'fiscal aggregate helper is not an exposed client RPC'
);

SELECT ok(
  has_function_privilege('authenticated', 'public.mark_agency_pending()', 'EXECUTE'),
  'agency registration can use the constrained pending-role RPC'
);

SELECT ok(
  has_function_privilege(
    'authenticated',
    'public.close_fiscal_period(uuid)',
    'EXECUTE'
  ),
  'authenticated clients can call the fiscal RPC which enforces SuperAdmin itself'
);

SELECT ok(
  EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'profiles'
      AND policyname = 'SuperAdmin reads all profiles'
  ),
  'SuperAdmin profile listing is protected by RLS'
);

SELECT ok(
  EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'guard_agency_platform_fields'
      AND NOT tgisinternal
  ),
  'agency plan and approval fields are protected by a database trigger'
);

SELECT throws_ok(
  $$
    INSERT INTO public.agency_invitations (tenant_id, email, role_name)
    VALUES (gen_random_uuid(), 'role-escalation@example.invalid', 'SuperAdmin')
  $$,
  'P0001',
  'No se pueden asignar roles administrativos de plataforma mediante invitaciones',
  'direct invitations cannot assign the platform administrator role'
);

SELECT * FROM finish();
ROLLBACK;
