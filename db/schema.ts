// THOTH evidence ledger — append-only, SHA-512 hash-chained.
// Immutability (veto triggers), chain linkage enforcement, FORCE RLS and privilege revocation
// are defined in the custom migration netlify/database/migrations/*_add_ledger_immutability_controls.
import { sql } from "drizzle-orm";
import { bigint, char, check, index, pgSchema, text, timestamp } from "drizzle-orm/pg-core";

export const omni333 = pgSchema("omni333");

export const evidenceLedger = omni333.table(
  "evidence_ledger",
  {
    seq: bigint("seq", { mode: "number" }).primaryKey(),
    entryType: text("entry_type").notNull(),
    subjectRef: text("subject_ref").notNull(),
    actorAri: text("actor_ari").notNull(),
    actorType: text("actor_type").notNull(),
    clearanceLevel: text("clearance_level").notNull(),
    payloadJcs: text("payload_jcs").notNull(),
    recordedAt: timestamp("recorded_at", { withTimezone: true, precision: 3, mode: "date" }).notNull(),
    hashPrev: char("hash_prev", { length: 128 }).notNull().unique(),
    hashSelf: char("hash_self", { length: 128 }).notNull().unique(),
  },
  (t) => [
    index("evidence_ledger_subject_ref_idx").on(t.subjectRef, t.seq),
    check("evidence_ledger_seq_positive", sql`${t.seq} >= 1`),
    check("evidence_ledger_entry_type_valid", sql`${t.entryType} IN ('TAP_RESULT', 'EVIDENCE', 'CAB_VOTE')`),
    check("evidence_ledger_actor_type_valid", sql`${t.actorType} IN ('human', 'ci')`),
    check("evidence_ledger_clearance_valid", sql`${t.clearanceLevel} IN ('NV2', 'PV')`),
    check("evidence_ledger_actor_ari_valid", sql`${t.actorAri} LIKE 'ari:%'`),
    check("evidence_ledger_cab_vote_human", sql`${t.entryType} <> 'CAB_VOTE' OR ${t.actorType} = 'human'`),
    check("evidence_ledger_hash_prev_hex", sql`${t.hashPrev} ~ '^[0-9a-f]{128}$'`),
    check("evidence_ledger_hash_self_hex", sql`${t.hashSelf} ~ '^[0-9a-f]{128}$'`),
  ],
);
