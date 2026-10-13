// THOTH — evidence provenance. Pure hash-chain construction and verification over ledger rows.
// hash_self = SHA-512( JCS(header) || hash_prev ), where header binds every stored column
// except the hashes themselves, so any mutation of any field breaks the chain.

import { GENESIS_HASH, HASH_HEX_128, canonicalJson, ledgerHash } from "./engine.ts";

export interface LedgerRow {
  seq: number;
  entry_type: string;
  subject_ref: string;
  actor_ari: string;
  actor_type: string;
  clearance_level: string;
  payload_jcs: string;
  recorded_at: string; // ISO-8601 UTC with millisecond precision
  hash_prev: string;
  hash_self: string;
}

export type UnsealedRow = Omit<LedgerRow, "hash_prev" | "hash_self">;

export function entryHeader(row: UnsealedRow) {
  return {
    seq: row.seq,
    entry_type: row.entry_type,
    subject_ref: row.subject_ref,
    actor_ari: row.actor_ari,
    actor_type: row.actor_type,
    clearance_level: row.clearance_level,
    payload: JSON.parse(row.payload_jcs) as unknown,
    recorded_at: row.recorded_at,
  };
}

export async function sealRow(row: UnsealedRow, hashPrev: string): Promise<LedgerRow> {
  return { ...row, hash_prev: hashPrev, hash_self: await ledgerHash(entryHeader(row), hashPrev) };
}

export interface ChainVerification {
  ok: boolean;
  entries_verified: number;
  head_seq: number | null;
  head_hash: string;
  first_failure: { seq: number; reason: string } | null;
}

/** Verifies a full ledger ordered by seq ascending, starting at genesis. */
export async function verifyChain(rows: LedgerRow[]): Promise<ChainVerification> {
  let prev = GENESIS_HASH;
  let expectedSeq = 1;
  for (const row of rows) {
    const fail = (reason: string): ChainVerification =>
      ({ ok: false, entries_verified: expectedSeq - 1, head_seq: row.seq, head_hash: prev, first_failure: { seq: row.seq, reason } });
    if (row.seq !== expectedSeq) return fail("SEQUENCE_GAP");
    if (!HASH_HEX_128.test(row.hash_prev) || !HASH_HEX_128.test(row.hash_self)) return fail("MALFORMED_HASH");
    if (row.hash_prev !== prev) return fail("HASH_PREV_DISCONTINUITY");
    let canonicalOk = false;
    try { canonicalOk = canonicalJson(JSON.parse(row.payload_jcs)) === row.payload_jcs; } catch { canonicalOk = false; }
    if (!canonicalOk) return fail("PAYLOAD_NOT_CANONICAL");
    const expected = await ledgerHash(entryHeader(row), row.hash_prev);
    if (expected !== row.hash_self) return fail("HASH_SELF_MISMATCH");
    prev = row.hash_self;
    expectedSeq++;
  }
  return { ok: true, entries_verified: rows.length, head_seq: rows.length ? rows[rows.length - 1]!.seq : null, head_hash: prev, first_failure: null };
}
