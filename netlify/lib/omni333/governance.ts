// OMNI-333 governance constants. These values are the single source of truth used by the
// ANUBIS guard, the MA'AT gate, the THOTH ledger, the MCP server and the documentation.

export const PROGRAM = {
  artefact: "OMNI333_TRIAD_SENTINEL_CONSOLIDATED_DOSSIER_v2.6r9",
  program: "OMNI-333 Sovereign Governance Spine",
  jurisdiction: "AU_FED_SOVEREIGN",
  organisation: "Quantum Blockchain Ai",
  entity: "AUSTRALIAN SOVEREIGNTY DATA GOVERNANCE",
  jira_site: "australian-sovereignty-data-governance.atlassian.net",
  jira_project_key: "ASCC",
  audit_anchor: "0x333A",
  security_classification: "PSPF / PROTECTED",
  security_mode: "ENFORCEMENT_MODE_A",
} as const;

/** Unanimous Human CAB quorum required before a release gate can reach PASS. */
export const CAB_QUORUM_REQUIRED = 4;

/** Clearances permitted to read from or append to the evidence ledger. */
export const LEDGER_CLEARANCES = ["NV2", "PV"] as const;
export type Clearance = (typeof LEDGER_CLEARANCES)[number];

/** Actor types permitted to append evidence. Agents (models) have zero write authority. */
export const WRITE_ACTOR_TYPES = ["human", "ci"] as const;

export const ENTRY_TYPES = ["TAP_RESULT", "EVIDENCE", "CAB_VOTE"] as const;
export type EntryType = (typeof ENTRY_TYPES)[number];

export const CAB_DECISIONS = ["APPROVE", "REJECT", "ABSTAIN"] as const;
export type CabDecision = (typeof CAB_DECISIONS)[number];

/** Subject references are Jira issue keys (ASCC-127) or change request ids (CR-OMNI333-20261012-PROD). */
export const SUBJECT_REF = /^(?:[A-Z][A-Z0-9]+-\d+|CR-[A-Z0-9]+(?:-[A-Z0-9]+)*)$/;

/**
 * Governing invariant record. The authority fields are constants: no code path in this
 * repository grants model, database-write or deployment authority to an automated actor.
 */
export const AUTHORITY_INVARIANTS = {
  approval_authority: "HUMAN_CAB_ONLY",
  quorum_required: CAB_QUORUM_REQUIRED,
  model_authority: 0.0,
  database_write_authority: 0.0,
  deployment_authority: 0.0,
  production_authority: false,
} as const;

export const BASELINE_POSTURE = {
  artefact: PROGRAM.artefact,
  implementation_state: "CANDIDATE",
  execution_state: "NOT_EXECUTED",
  runtime_result: "UNKNOWN",
  gate_state: "BLOCKED",
  cab_decision: "NOT_EVIDENCED",
  quorum_achieved: false,
  seal_eligible: false,
  release_status: "NO_GO_FOR_PRODUCTION",
  state_transition: "NONE",
  ...AUTHORITY_INVARIANTS,
} as const;
