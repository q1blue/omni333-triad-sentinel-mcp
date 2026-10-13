// OMNI-333 Trust Boundary 1 — Deterministic Verification & Gate Engine.
// Zero LLM / generative dependencies and zero I/O: every function in this module
// is a pure function of its inputs so results are reproducible and auditable.

export type TapResult = "PASS" | "FAIL" | "INVALID" | "UNKNOWN";
export type GateState = TapResult | "BLOCKED";

export const GATE_STATES: readonly GateState[] = ["PASS", "FAIL", "INVALID", "UNKNOWN", "BLOCKED"];

export interface TapEnvelope {
  result: TapResult;
  reason_code: string | null;
  planned: number | null;
  observed: number;
  passed: number;
  failed: number;
  todo: number;
  skipped: number;
  diagnostics: string[];
}

// TAP 13/14 plan line, optionally carrying a skip reason ("1..0 # Skipped: no db").
const PLAN = /^1\.\.(\d+)(?:\s*#.*)?$/;
// Test point: "ok"/"not ok", optional number, optional description (dash optional),
// optional directive. Directives are case-insensitive and may be extended (SKIPPED).
const ASSERT = /^(ok|not ok)\b(?:\s+(\d+))?(?:\s*-?\s*([^#]*?))?\s*(?:#\s*(TODO|SKIP)\S*\s*(.*))?$/i;
const VERSION = /^TAP version (13|14)$/i;
const YAML_START = /^\s+---\s*$/;
const YAML_END = /^\s+\.\.\.\s*$/;

/**
 * Parses a TAP (Test Anything Protocol) stream such as pgTAP or `node --test` output.
 * Fail-closed: any record that is not understood yields INVALID, never PASS.
 * Nested subtests are not supported and therefore surface as UNKNOWN_RECORD.
 */
export function parseTap(stream: string): TapEnvelope {
  let plan: number | null = null;
  let invalid: string | null = null;
  const seen: number[] = [];
  const diagnostics: string[] = [];
  let passed = 0, failed = 0, todo = 0, skipped = 0, auto = 1;
  let inYaml = false;
  let sawRecord = false;

  for (const raw of stream.split(/\r?\n/)) {
    if (inYaml) {
      if (YAML_END.test(raw)) inYaml = false;
      else diagnostics.push(raw.trim());
      continue;
    }
    const line = raw.trim();
    if (!line) continue;
    if (VERSION.test(line)) {
      if (sawRecord) { invalid = "MISPLACED_VERSION"; break; }
      sawRecord = true;
      continue;
    }
    sawRecord = true;
    if (YAML_START.test(raw)) {
      if (seen.length === 0) { invalid = "ORPHAN_YAML_BLOCK"; break; }
      inYaml = true;
      continue;
    }
    if (line.startsWith("#")) { diagnostics.push(line.replace(/^#\s*/, "")); continue; }
    if (/^bail out!/i.test(line)) { invalid = "BAIL_OUT"; diagnostics.push(line); break; }
    if (line.startsWith("1..")) {
      const m = PLAN.exec(line);
      if (!m) { invalid = "INVALID_PLAN"; break; }
      if (plan !== null) { invalid = "DUPLICATE_PLAN"; break; }
      plan = Number(m[1]);
      continue;
    }
    const m = ASSERT.exec(line);
    if (m) {
      const num = m[2] ? Number(m[2]) : auto;
      if (seen.includes(num)) { invalid = "DUPLICATE_TEST_NUMBER"; break; }
      seen.push(num); auto = num + 1;
      const dir = m[4]?.toUpperCase();
      if (dir === "TODO") todo++;
      else if (dir === "SKIP") skipped++;
      else if ((m[1] ?? "").toLowerCase() === "ok") passed++;
      else failed++;
      continue;
    }
    invalid = "UNKNOWN_RECORD";
    break;
  }
  if (!invalid && inYaml) invalid = "UNTERMINATED_YAML_BLOCK";
  const observed = seen.length;
  if (!invalid) {
    if (plan === null) invalid = "MISSING_PLAN";
    else if (observed !== plan) invalid = "PLAN_COUNT_MISMATCH";
    else if (seen.some((n, i) => n !== i + 1)) invalid = "TEST_NUMBER_GAP";
  }
  let result: TapResult, reason: string | null;
  if (invalid) { result = "INVALID"; reason = invalid; }
  else if (failed > 0) { result = "FAIL"; reason = "ASSERTION_FAILED"; }
  else if (passed === 0) { result = "UNKNOWN"; reason = "NO_EXECUTED_ASSERTIONS"; }
  else { result = "PASS"; reason = null; }
  return { result, reason_code: reason, planned: plan, observed, passed, failed, todo, skipped, diagnostics };
}

// Precedence: INVALID > FAIL > BLOCKED > UNKNOWN > PASS. Empty input is BLOCKED (fail-closed).
const RANK: Record<GateState, number> = { INVALID: 4, FAIL: 3, BLOCKED: 2, UNKNOWN: 1, PASS: 0 };
export function aggregate(states: GateState[]): GateState {
  if (states.length === 0) return "BLOCKED";
  return states.reduce((a, b) => (RANK[b] > RANK[a] ? b : a));
}

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 * - Object members sorted by UTF-16 code units (JS default sort order).
 * - Numbers serialised with ECMAScript Number.prototype.toString (as JSON.stringify does).
 * - Strings must be well-formed Unicode (lone surrogates are rejected, per I-JSON).
 * - Non-JSON values (undefined, functions, bigint, symbols, non-finite numbers,
 *   class instances such as Date/Map) are rejected instead of being silently coerced.
 */
export function canonicalJson(v: unknown): string {
  if (typeof v === "number" && !Number.isFinite(v)) throw new Error("JCS_NON_FINITE_NUMBER");
  if (v === undefined || typeof v === "function" || typeof v === "bigint" || typeof v === "symbol")
    throw new Error("JCS_UNSUPPORTED_TYPE");
  if (typeof v === "string") {
    if (!v.isWellFormed()) throw new Error("JCS_LONE_SURROGATE");
    return JSON.stringify(v);
  }
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const proto = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) throw new Error("JCS_UNSUPPORTED_TYPE");
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).sort().map((k) => {
    if (!k.isWellFormed()) throw new Error("JCS_LONE_SURROGATE");
    return `${JSON.stringify(k)}:${canonicalJson(o[k])}`;
  }).join(",")}}`;
}

async function digestHex(algorithm: "SHA-256" | "SHA-512", s: string): Promise<string> {
  const buf = await crypto.subtle.digest(algorithm, new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const sha256Hex = (s: string) => digestHex("SHA-256", s);
export const sha512Hex = (s: string) => digestHex("SHA-512", s);

/** SHA-512 hash-chain link: H(JCS(payload) || hash_prev). Produces 128 hex chars (char(128)). */
export async function ledgerHash(payload: unknown, hashPrev: string): Promise<string> {
  return sha512Hex(canonicalJson(payload) + hashPrev);
}

/** Genesis predecessor for the first ledger entry. */
export const GENESIS_HASH = "0".repeat(128);
export const HASH_HEX_128 = /^[0-9a-f]{128}$/;

/**
 * MA'AT gate: combines the deterministic inputs. A release can only reach PASS when the TAP
 * evidence passed, the ANUBIS guard passed, the THOTH chain verified, and a Human CAB
 * decision is evidenced. Anything else resolves to the highest-precedence failure state.
 */
export function maatGate(tap: GateState, guardOk: boolean, hashOk: boolean, cabEvidenced: boolean): GateState {
  const states: GateState[] = [tap, guardOk ? "PASS" : "FAIL", hashOk ? "PASS" : "INVALID"];
  if (!cabEvidenced) states.push("BLOCKED");
  return aggregate(states);
}
