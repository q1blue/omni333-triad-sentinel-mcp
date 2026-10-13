// MA'AT — release gate arbiter. Pure evaluation of a subject (Jira issue / change request)
// from verified THOTH ledger rows. Default posture is BLOCKED; PASS requires passing TAP
// evidence, an intact hash chain, and a unanimous Human CAB quorum recorded after the
// latest evidence. A PASS makes a release *eligible*; it never deploys anything.

import { aggregate, maatGate, type GateState, type TapEnvelope } from "./engine.ts";
import { AUTHORITY_INVARIANTS, CAB_QUORUM_REQUIRED, type CabDecision } from "./governance.ts";
import type { ChainVerification, LedgerRow } from "./thoth.ts";

export interface SuiteState { suite: string; seq: number; result: GateState; reason_code: string | null }
export interface VoteState { actor_ari: string; decision: CabDecision; seq: number }

export interface GateEvaluation {
  subject_ref: string;
  gate_state: GateState;
  reasons: string[];
  tap: { state: GateState; suites: SuiteState[] };
  ledger: { hash_ok: boolean; entries_verified: number; head_seq: number | null; first_failure: ChainVerification["first_failure"] };
  cab: {
    quorum_required: number;
    approvals: number;
    rejections: number;
    abstentions: number;
    quorum_achieved: boolean;
    decision: "NOT_EVIDENCED" | "INSUFFICIENT_QUORUM" | "REJECTED" | "APPROVED";
    counted_after_seq: number | null;
    votes: VoteState[];
  };
  seal_eligible: boolean;
  release_status: "NO_GO_FOR_PRODUCTION" | "CAB_APPROVED_RELEASE_ELIGIBLE";
  approval_authority: typeof AUTHORITY_INVARIANTS.approval_authority;
  model_authority: 0;
  database_write_authority: 0;
  deployment_authority: 0;
  production_authority: false;
}

const parse = (row: LedgerRow): Record<string, unknown> => {
  try { const v = JSON.parse(row.payload_jcs); return v && typeof v === "object" ? v : {}; } catch { return {}; }
};

export function evaluateGate(subjectRef: string, subjectRows: LedgerRow[], chain: ChainVerification, guardOk: boolean): GateEvaluation {
  const rows = subjectRows.filter((r) => r.subject_ref === subjectRef).sort((a, b) => a.seq - b.seq);
  const reasons: string[] = [];

  const latestBySuite = new Map<string, SuiteState>();
  let lastEvidenceSeq: number | null = null;
  for (const row of rows) {
    if (row.entry_type === "TAP_RESULT" || row.entry_type === "EVIDENCE") lastEvidenceSeq = row.seq;
    if (row.entry_type !== "TAP_RESULT") continue;
    const p = parse(row);
    const env = p.envelope as Partial<TapEnvelope> | undefined;
    const result = (["PASS", "FAIL", "INVALID", "UNKNOWN"] as const).find((s) => s === env?.result) ?? "INVALID";
    const suite = typeof p.suite === "string" ? p.suite : "default";
    latestBySuite.set(suite, { suite, seq: row.seq, result, reason_code: env?.reason_code ?? (result === "INVALID" ? "MALFORMED_TAP_ENTRY" : null) });
  }
  const suites = [...latestBySuite.values()].sort((a, b) => a.suite.localeCompare(b.suite));
  const tapState: GateState = suites.length ? aggregate(suites.map((s) => s.result)) : "BLOCKED";
  if (!suites.length) reasons.push("NO_TAP_EVIDENCE");
  for (const s of suites) if (s.result !== "PASS") reasons.push(`TAP_${s.result}:${s.suite}`);

  const latestVote = new Map<string, VoteState>();
  for (const row of rows) {
    if (row.entry_type !== "CAB_VOTE" || row.actor_type !== "human") continue;
    if (lastEvidenceSeq !== null && row.seq <= lastEvidenceSeq) continue; // stale: predates latest evidence
    const decision = parse(row).decision;
    if (decision !== "APPROVE" && decision !== "REJECT" && decision !== "ABSTAIN") continue;
    latestVote.set(row.actor_ari, { actor_ari: row.actor_ari, decision, seq: row.seq });
  }
  const votes = [...latestVote.values()].sort((a, b) => a.seq - b.seq);
  const approvals = votes.filter((v) => v.decision === "APPROVE").length;
  const rejections = votes.filter((v) => v.decision === "REJECT").length;
  const abstentions = votes.filter((v) => v.decision === "ABSTAIN").length;
  const quorumAchieved = rejections === 0 && approvals >= CAB_QUORUM_REQUIRED;
  const decision = votes.length === 0 ? "NOT_EVIDENCED" : rejections > 0 ? "REJECTED" : quorumAchieved ? "APPROVED" : "INSUFFICIENT_QUORUM";
  if (decision !== "APPROVED") reasons.push(`CAB_${decision}`);
  if (lastEvidenceSeq === null) reasons.push("CAB_REQUIRES_PRIOR_EVIDENCE");

  if (!chain.ok) reasons.push(`LEDGER_${chain.first_failure?.reason ?? "UNVERIFIED"}`);
  if (!guardOk) reasons.push("GUARD_FAILED");

  const cabEvidenced = quorumAchieved && lastEvidenceSeq !== null;
  const gateState = maatGate(tapState, guardOk, chain.ok, cabEvidenced);
  const pass = gateState === "PASS";

  return {
    subject_ref: subjectRef,
    gate_state: gateState,
    reasons,
    tap: { state: tapState, suites },
    ledger: { hash_ok: chain.ok, entries_verified: chain.entries_verified, head_seq: chain.head_seq, first_failure: chain.first_failure },
    cab: {
      quorum_required: CAB_QUORUM_REQUIRED, approvals, rejections, abstentions,
      quorum_achieved: quorumAchieved, decision, counted_after_seq: lastEvidenceSeq, votes,
    },
    seal_eligible: pass,
    release_status: pass ? "CAB_APPROVED_RELEASE_ELIGIBLE" : "NO_GO_FOR_PRODUCTION",
    approval_authority: AUTHORITY_INVARIANTS.approval_authority,
    model_authority: 0,
    database_write_authority: 0,
    deployment_authority: 0,
    production_authority: false,
  };
}
