/**
 * Success-stamp reader: the follow-up layer to the liveness-of-guard fixture.
 *
 * PR #14 proved that a guard which actually runs can distinguish CLEAN, RED,
 * and BLIND, and that a clean run stays silent while writing a success stamp.
 * This file reads that stamp from outside the guard. It closes the residual:
 * silence from a disabled, masked, uninstalled, or never-scheduled guard is
 * byte-identical to silence from a healthy guard unless something else reads a
 * recent control stamp.
 *
 * This is monitoring/liveness evidence only. It does not settle the subject of
 * the audit. A stale or missing control is BLIND/UNKNOWN — a claim about our
 * instrument — not RED, which would be a claim about the subject.
 */

/** A subject input that made the guard reject. Presence means the guard found RED. */
export interface GuardFireRecord {
  at: string;
  input: string;
}

/**
 * Readable JSON-ish stamp schema for guard liveness.
 *
 * `guard_control_at` is the liveness proof: a known-bad control was recently
 * fed into the guard and rejected. `control_corpus_hash` prevents a shrinking
 * control corpus from looking fresh forever. `control_max_age_ms` is the
 * explicit freshness rule. `guard_skipped` makes enumerator blind spots visible
 * instead of letting a partial scan present as full coverage.
 */
export interface GuardStamp {
  unit: string;
  stamped_at: string;
  guard_control_at?: string | null;
  control_corpus_hash?: string | null;
  control_max_age_ms: number;
  guard_skipped?: string[];
  guard_fired_at?: GuardFireRecord | null;
}

export type StampReaderOutcome = "OK" | "RED" | "BLIND";
export type Coverage = "complete" | "has_exclusions" | "unaudited";

export interface StampReaderDecision {
  unit: string;
  outcome: StampReaderOutcome;
  alerted: boolean;
  reason:
    | "subject_rejected"
    | "fresh_control_no_subject_rejection"
    | "missing_control"
    | "stale_control"
    | "invalid_control_timestamp"
    | "missing_control_corpus_hash"
    | "invalid_control_max_age"
    | "coverage_unaudited";
  coverage: Coverage;
  control_age_ms?: number;
  guard_skipped: string[];
}

function parseTimeMs(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function coverageOf(stamp: GuardStamp): { coverage: Coverage; skipped: string[] | null } {
  if (!Array.isArray(stamp.guard_skipped)) {
    return { coverage: "unaudited", skipped: null };
  }
  return {
    coverage: stamp.guard_skipped.length === 0 ? "complete" : "has_exclusions",
    skipped: stamp.guard_skipped,
  };
}

function blind(
  stamp: GuardStamp,
  reason: Extract<StampReaderDecision["reason"],
    | "missing_control"
    | "stale_control"
    | "invalid_control_timestamp"
    | "missing_control_corpus_hash"
    | "invalid_control_max_age"
    | "coverage_unaudited">,
  coverage: Coverage,
  guardSkipped: string[],
  controlAgeMs?: number,
): StampReaderDecision {
  return {
    unit: stamp.unit,
    outcome: "BLIND",
    alerted: true,
    reason,
    coverage,
    control_age_ms: controlAgeMs,
    guard_skipped: guardSkipped,
  };
}

/**
 * Read a success stamp and decide whether silence is meaningful.
 *
 * Interpretation rules:
 * - missing/stale control => BLIND, not OK;
 * - missing `guard_skipped` => BLIND because coverage was not audited;
 * - present `guard_fired_at` with fresh liveness proof => RED;
 * - recent control + no subject rejection => OK, silent, with exclusions surfaced.
 */
export function readGuardStamp(stamp: GuardStamp, now: Date = new Date()): StampReaderDecision {
  const { coverage, skipped } = coverageOf(stamp);
  if (skipped === null) {
    return blind(stamp, "coverage_unaudited", coverage, []);
  }

  if (!stamp.control_corpus_hash) {
    return blind(stamp, "missing_control_corpus_hash", coverage, skipped);
  }

  if (!Number.isFinite(stamp.control_max_age_ms) || stamp.control_max_age_ms <= 0) {
    return blind(stamp, "invalid_control_max_age", coverage, skipped);
  }

  const controlAtMs = parseTimeMs(stamp.guard_control_at);
  if (stamp.guard_control_at && controlAtMs === null) {
    return blind(stamp, "invalid_control_timestamp", coverage, skipped);
  }
  if (controlAtMs === null) {
    return blind(stamp, "missing_control", coverage, skipped);
  }

  const controlAgeMs = now.getTime() - controlAtMs;
  if (controlAgeMs < 0 || controlAgeMs > stamp.control_max_age_ms) {
    return blind(stamp, "stale_control", coverage, skipped, controlAgeMs);
  }

  if (stamp.guard_fired_at) {
    return {
      unit: stamp.unit,
      outcome: "RED",
      alerted: true,
      reason: "subject_rejected",
      coverage,
      control_age_ms: controlAgeMs,
      guard_skipped: skipped,
    };
  }

  return {
    unit: stamp.unit,
    outcome: "OK",
    alerted: false,
    reason: "fresh_control_no_subject_rejection",
    coverage,
    control_age_ms: controlAgeMs,
    guard_skipped: skipped,
  };
}
