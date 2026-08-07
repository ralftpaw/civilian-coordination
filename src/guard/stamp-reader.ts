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
 *
 * `control_rejections_observed` / `control_rejections_expected` close the gap
 * the three fields above leave open. They record that the control run was
 * INVOKED; they do not record that it FIRED. A guard can drift so that the
 * known-bad corpus stops tripping it while the producer keeps running the
 * control on schedule: the timestamp stays fresh, the hash still matches
 * because the corpus never changed, and the reader returns OK — stable, fresh,
 * and vacuous. Only a count of what the control actually rejected separates a
 * live control from a ceremonial one.
 */
export interface GuardStamp {
  unit: string;
  stamped_at: string;
  guard_control_at?: string | null;
  control_corpus_hash?: string | null;
  control_max_age_ms: number;
  /** How many known-bad entries the control run actually caused the guard to reject. */
  control_rejections_observed?: number | null;
  /** How many the corpus named by `control_corpus_hash` is supposed to trip. */
  control_rejections_expected?: number | null;
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
    | "missing_control_result"
    | "invalid_control_expected"
    | "control_caught_nothing"
    | "control_under_rejected"
    | "coverage_unaudited";
  coverage: Coverage;
  control_age_ms?: number;
  /** Echoed so a reader can see the evidence the outcome turned on. */
  control_rejections_observed?: number;
  control_rejections_expected?: number;
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
    | "missing_control_result"
    | "invalid_control_expected"
    | "control_caught_nothing"
    | "control_under_rejected"
    | "coverage_unaudited">,
  coverage: Coverage,
  guardSkipped: string[],
  controlAgeMs?: number,
  counts?: { observed?: number; expected?: number },
): StampReaderDecision {
  return {
    unit: stamp.unit,
    outcome: "BLIND",
    alerted: true,
    reason,
    coverage,
    control_age_ms: controlAgeMs,
    control_rejections_observed: counts?.observed,
    control_rejections_expected: counts?.expected,
    guard_skipped: guardSkipped,
  };
}

/** A non-negative integer, and not NaN/Infinity/"3"/null. */
function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

/**
 * Read a success stamp and decide whether silence is meaningful.
 *
 * Interpretation rules:
 * - missing/stale control => BLIND, not OK;
 * - missing `guard_skipped` => BLIND because coverage was not audited;
 * - missing rejection counts => BLIND: the control's invocation is proved, its
 *   firing is not;
 * - `control_rejections_expected === 0` => BLIND: a control that is supposed to
 *   catch nothing is satisfied by an absent guard;
 * - `control_rejections_observed === 0` => BLIND: the drifted-guard signature;
 * - observed < expected => BLIND: the control is partially dead;
 * - present `guard_fired_at` with a fresh AND FIRING control => RED;
 * - fresh firing control + no subject rejection => OK, silent, exclusions surfaced.
 *
 * Every one of the new outcomes is BLIND rather than RED, for the reason the
 * rest of this file already turns on: a dead control is a fact about our
 * instrument, never evidence against the subject.
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

  // The control ran recently against a named corpus. Everything above proves
  // INVOCATION. What follows is the only evidence that it FIRED.
  const observed = stamp.control_rejections_observed;
  const expected = stamp.control_rejections_expected;

  if (!isCount(observed) || !isCount(expected)) {
    // Absent result evidence is not a pass. A stamp that never says what the
    // control caught cannot distinguish a working guard from a drifted one,
    // and that is a statement about the instrument.
    return blind(stamp, "missing_control_result", coverage, skipped, controlAgeMs, {
      observed: isCount(observed) ? observed : undefined,
      expected: isCount(expected) ? expected : undefined,
    });
  }

  if (expected === 0) {
    // A corpus expected to trip nothing certifies nothing: observed === expected
    // is then satisfied by a guard that has been deleted. This is the same
    // vacuous-denominator hole the rest of the schema exists to close, and it
    // would otherwise be reachable by a one-character edit to the producer.
    return blind(stamp, "invalid_control_expected", coverage, skipped, controlAgeMs, {
      observed,
      expected,
    });
  }

  if (observed === 0) {
    // Called out separately from a partial shortfall: a control that caught
    // nothing at all is the drifted-guard signature, not a tuning problem.
    return blind(stamp, "control_caught_nothing", coverage, skipped, controlAgeMs, {
      observed,
      expected,
    });
  }

  if (observed < expected) {
    return blind(stamp, "control_under_rejected", coverage, skipped, controlAgeMs, {
      observed,
      expected,
    });
  }

  if (stamp.guard_fired_at) {
    return {
      unit: stamp.unit,
      outcome: "RED",
      alerted: true,
      reason: "subject_rejected",
      coverage,
      control_age_ms: controlAgeMs,
      control_rejections_observed: observed,
      control_rejections_expected: expected,
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
    control_rejections_observed: observed,
    control_rejections_expected: expected,
    guard_skipped: skipped,
  };
}
