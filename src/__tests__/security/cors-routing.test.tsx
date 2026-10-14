import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = resolve(__dirname, "..", "..", "..");

describe("Security: CSP Headers", () => {
  it("index.html has Content-Security-Policy meta tag", () => {
    const indexPath = resolve(ROOT, "index.html");
    const html = readFileSync(indexPath, "utf-8");

    expect(html).toContain("Content-Security-Policy");
    expect(html).toContain("default-src 'self'");
  });
});
