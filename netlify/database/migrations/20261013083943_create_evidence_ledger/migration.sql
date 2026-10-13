CREATE SCHEMA "omni333";
--> statement-breakpoint
CREATE TABLE "omni333"."evidence_ledger" (
	"seq" bigint PRIMARY KEY,
	"entry_type" text NOT NULL,
	"subject_ref" text NOT NULL,
	"actor_ari" text NOT NULL,
	"actor_type" text NOT NULL,
	"clearance_level" text NOT NULL,
	"payload_jcs" text NOT NULL,
	"recorded_at" timestamp(3) with time zone NOT NULL,
	"hash_prev" char(128) NOT NULL UNIQUE,
	"hash_self" char(128) NOT NULL UNIQUE,
	CONSTRAINT "evidence_ledger_seq_positive" CHECK ("seq" >= 1),
	CONSTRAINT "evidence_ledger_entry_type_valid" CHECK ("entry_type" IN ('TAP_RESULT', 'EVIDENCE', 'CAB_VOTE')),
	CONSTRAINT "evidence_ledger_actor_type_valid" CHECK ("actor_type" IN ('human', 'ci')),
	CONSTRAINT "evidence_ledger_clearance_valid" CHECK ("clearance_level" IN ('NV2', 'PV')),
	CONSTRAINT "evidence_ledger_actor_ari_valid" CHECK ("actor_ari" LIKE 'ari:%'),
	CONSTRAINT "evidence_ledger_cab_vote_human" CHECK ("entry_type" <> 'CAB_VOTE' OR "actor_type" = 'human'),
	CONSTRAINT "evidence_ledger_hash_prev_hex" CHECK ("hash_prev" ~ '^[0-9a-f]{128}$'),
	CONSTRAINT "evidence_ledger_hash_self_hex" CHECK ("hash_self" ~ '^[0-9a-f]{128}$')
);
--> statement-breakpoint
CREATE INDEX "evidence_ledger_subject_ref_idx" ON "omni333"."evidence_ledger" ("subject_ref","seq");