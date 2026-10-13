// ANUBIS — transport & identity guard. Strictly fail-closed:
//  * HTTPS-only transport.
//  * Bearer JWT must be cryptographically verified (signature, issuer, audience, expiry)
//    against a configured JWKS endpoint or HS256 secret. Unverified tokens are never trusted.
//  * Required claims: sub, exp, app_metadata.actor_ari, app_metadata.clearance_level.
//  * Anonymous roles and anon API keys are always rejected.
//  * Missing configuration denies every request (AUTH_NOT_CONFIGURED) — there is no fallback.

import { createRemoteJWKSet, decodeJwt, errors, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";
import { LEDGER_CLEARANCES, WRITE_ACTOR_TYPES, type Clearance } from "./governance.ts";

export type ActorType = "human" | "ci" | "agent" | "unspecified";

export interface Principal {
  sub: string;
  actor_ari: string;
  clearance_level: Clearance;
  actor_type: ActorType;
  cab_member: boolean;
  role: string | null;
}

export interface GuardResult {
  ok: boolean;
  status: 200 | 401 | 403 | 503;
  reasons: string[];
  principal: Principal | null;
  /** Verified claims, used only to bind database RLS context. Never returned to clients. */
  claims: JWTPayload | null;
}

type KeySource = { kind: "jwks"; key: JWTVerifyGetKey } | { kind: "hs256"; key: Uint8Array };
interface AuthConfig { source: KeySource; issuer: string; audience: string; algorithms: string[] }

const ASYMMETRIC_ALGS = ["RS256", "PS256", "ES256", "ES384", "EdDSA"];
const jwksCache = new Map<string, JWTVerifyGetKey>();

export function loadAuthConfig(env: Record<string, string | undefined> = process.env): AuthConfig | { error: string } {
  const issuer = env.OMNI333_JWT_ISSUER?.trim();
  const audience = env.OMNI333_JWT_AUDIENCE?.trim();
  const jwksUrl = env.OMNI333_JWKS_URL?.trim();
  const secret = env.OMNI333_JWT_HS256_SECRET;
  if (!issuer || !audience) return { error: "AUTH_NOT_CONFIGURED" };
  if (jwksUrl && secret) return { error: "AUTH_AMBIGUOUS_KEY_SOURCE" };
  if (jwksUrl) {
    let url: URL;
    try { url = new URL(jwksUrl); } catch { return { error: "AUTH_JWKS_URL_MALFORMED" }; }
    if (url.protocol !== "https:") return { error: "AUTH_JWKS_URL_NOT_HTTPS" };
    let key = jwksCache.get(url.href);
    if (!key) { key = createRemoteJWKSet(url); jwksCache.set(url.href, key); }
    return { source: { kind: "jwks", key }, issuer, audience, algorithms: ASYMMETRIC_ALGS };
  }
  if (secret) {
    if (secret.length < 32) return { error: "AUTH_SECRET_TOO_SHORT" };
    return { source: { kind: "hs256", key: new TextEncoder().encode(secret) }, issuer, audience, algorithms: ["HS256"] };
  }
  return { error: "AUTH_NOT_CONFIGURED" };
}

function isAnonCredential(value: string): boolean {
  if (!value) return false;
  if (value.toLowerCase().includes("anon")) return true;
  try { return decodeJwt(value).role === "anon"; } catch { return false; }
}

function verificationReason(e: unknown): string {
  if (e instanceof errors.JWTExpired) return "JWT_EXPIRED";
  if (e instanceof errors.JWTClaimValidationFailed) return `JWT_CLAIM_INVALID_${e.claim.toUpperCase()}`;
  if (e instanceof errors.JWSSignatureVerificationFailed) return "JWT_SIGNATURE_INVALID";
  if (e instanceof errors.JOSEAlgNotAllowed) return "JWT_ALG_NOT_ALLOWED";
  if (e instanceof errors.JWKSNoMatchingKey) return "JWT_NO_MATCHING_KEY";
  if (e instanceof errors.JWKSTimeout || e instanceof errors.JWKSInvalid) return "JWKS_UNAVAILABLE";
  if (e instanceof errors.JWSInvalid || e instanceof errors.JWTInvalid) return "MALFORMED_JWT";
  return "JWT_VERIFICATION_FAILED";
}

const UNAVAILABLE = new Set(["AUTH_NOT_CONFIGURED", "AUTH_AMBIGUOUS_KEY_SOURCE", "AUTH_JWKS_URL_MALFORMED",
  "AUTH_JWKS_URL_NOT_HTTPS", "AUTH_SECRET_TOO_SHORT", "JWKS_UNAVAILABLE"]);
const UNAUTHENTICATED = new Set(["MISSING_SOVEREIGN_JWT", "MALFORMED_JWT", "JWT_EXPIRED", "JWT_SIGNATURE_INVALID",
  "JWT_ALG_NOT_ALLOWED", "JWT_NO_MATCHING_KEY", "JWT_VERIFICATION_FAILED"]);

function statusFor(reasons: string[]): GuardResult["status"] {
  if (reasons.length === 0) return 200;
  if (reasons.some((r) => UNAVAILABLE.has(r))) return 503;
  if (reasons.some((r) => UNAUTHENTICATED.has(r) || r.startsWith("JWT_CLAIM_INVALID_"))) return 401;
  return 403;
}

export interface GuardInput { url: string; authorization: string | null; apikey: string | null }

export async function anubisGuard(input: GuardInput, env: Record<string, string | undefined> = process.env): Promise<GuardResult> {
  const reasons: string[] = [];
  const add = (r: string) => { if (!reasons.includes(r)) reasons.push(r); };

  let https = false;
  try { https = new URL(input.url).protocol === "https:"; } catch { add("MALFORMED_URL"); }
  if (!https) add("NON_HTTPS_TRANSPORT");

  if (isAnonCredential(input.apikey ?? "")) add("ANON_KEY_PROHIBITED");

  const auth = input.authorization ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token) add("MISSING_SOVEREIGN_JWT");

  const config = loadAuthConfig(env);
  if ("error" in config) add(config.error);

  let claims: JWTPayload | null = null;
  if (token && !("error" in config)) {
    try {
      const { payload } = await jwtVerify(token, config.source.key as never, {
        issuer: config.issuer,
        audience: config.audience,
        algorithms: config.algorithms,
        requiredClaims: ["exp", "sub"],
        clockTolerance: 30,
      });
      claims = payload;
    } catch (e) {
      add(verificationReason(e));
    }
  }

  let principal: Principal | null = null;
  if (claims) {
    if (claims.role === "anon") add("ANON_KEY_PROHIBITED");
    const meta = (claims.app_metadata && typeof claims.app_metadata === "object" ? claims.app_metadata : {}) as Record<string, unknown>;
    const actorAri = typeof meta.actor_ari === "string" ? meta.actor_ari.trim() : "";
    const clearance = typeof meta.clearance_level === "string" ? meta.clearance_level.trim() : "";
    if (!actorAri) add("MISSING_CLAIM_ACTOR_ARI");
    else if (!actorAri.startsWith("ari:")) add("MALFORMED_CLAIM_ACTOR_ARI");
    if (!clearance) add("MISSING_CLAIM_CLEARANCE_LEVEL");
    else if (!(LEDGER_CLEARANCES as readonly string[]).includes(clearance)) add("CLEARANCE_INSUFFICIENT");
    const actorType = (["human", "ci", "agent"] as const).find((t) => t === meta.actor_type) ?? "unspecified";
    if (reasons.length === 0) {
      principal = {
        sub: String(claims.sub),
        actor_ari: actorAri,
        clearance_level: clearance as Clearance,
        actor_type: actorType,
        cab_member: meta.cab_member === true,
        role: typeof claims.role === "string" ? claims.role : null,
      };
    }
  }

  const ok = reasons.length === 0 && principal !== null;
  return { ok, status: ok ? 200 : statusFor(reasons), reasons, principal: ok ? principal : null, claims: ok ? claims : null };
}

export function guardRequest(req: Request): Promise<GuardResult> {
  return anubisGuard({ url: req.url, authorization: req.headers.get("authorization"), apikey: req.headers.get("apikey") });
}

/** Write authority: only verified human or CI actors may append evidence. Agents never write. */
export function writeDenial(p: Principal): string | null {
  return (WRITE_ACTOR_TYPES as readonly string[]).includes(p.actor_type) ? null : "WRITE_AUTHORITY_DENIED_ACTOR_TYPE";
}
