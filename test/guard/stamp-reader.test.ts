import { describe, expect, it } from "vitest";

import {
  readGuardStamp,
  type GuardStamp,
  type StampReaderDecision,
} from "../../src/guard/stamp-reader.js";

const now = new Date("2026-07-31T12:00:00.000Z");

function freshStamp(overrides: Partial<GuardStamp> = {}): GuardStamp {
  return {
    unit: "audit.service",
    stamped_at: "2026-07-31T11:59:00.000Z",
    guard_control_at: "2026-07-31T11:55:00.000Z",
    control_corpus_hash: "sha256:known-bad-corpus-v1",
    control_max_age_ms: 10 * 60 * 1000,
    guard_skipped: [],
    ...overrides,
  };
}

function unconditionalAlertReader(stamp: GuardStamp): StampReaderDecision {
  return {
    unit: stamp.unit,
    outcome: "RED",
    alerted: true,
    reason: "subject_rejected",
    coverage: "complete",
    guard_skipped: [],
  };
}

describe("success-stamp reader — liveness proof for the guard itself", () => {
  it("MUST-ALLOW: fresh control plus no subject rejection stays silent", () => {
    const decision = readGuardStamp(freshStamp(), now);

    expect(decision).toMatchObject({
      outcome: "OK",
      alerted: false,
      reason: "fresh_control_no_subject_rejection",
      coverage: "complete",
      control_age_ms: 5 * 60 * 1000,
      guard_skipped: [],
    });
  });

  it("missing control is BLIND, not RED and not OK", () => {
    const decision = readGuardStamp(freshStamp({ guard_control_at: null }), now);

    expect(decision.outcome).toBe("BLIND");
    expect(decision.alerted).toBe(true);
    expect(decision.reason).toBe("missing_control");
  });

  it("stale control is BLIND, using the explicit max-age field", () => {
    const decision = readGuardStamp(
      freshStamp({
        guard_control_at: "2026-07-31T11:00:00.000Z",
        control_max_age_ms: 10 * 60 * 1000,
      }),
      now,
    );

    expect(decision.outcome).toBe("BLIND");
    expect(decision.reason).toBe("stale_control");
    expect(decision.control_age_ms).toBe(60 * 60 * 1000);
  });

  it("invalid control timestamp is BLIND rather than silently accepted", () => {
    const decision = readGuardStamp(freshStamp({ guard_control_at: "not-a-date" }), now);

    expect(decision.outcome).toBe("BLIND");
    expect(decision.reason).toBe("invalid_control_timestamp");
  });

  it("missing control corpus hash is BLIND because a shrinking corpus can fake freshness", () => {
    const decision = readGuardStamp(freshStamp({ control_corpus_hash: null }), now);

    expect(decision.outcome).toBe("BLIND");
    expect(decision.reason).toBe("missing_control_corpus_hash");
  });

  it("invalid freshness policy is BLIND because the timestamp has no contract", () => {
    const decision = readGuardStamp(freshStamp({ control_max_age_ms: 0 }), now);

    expect(decision.outcome).toBe("BLIND");
    expect(decision.reason).toBe("invalid_control_max_age");
  });

  it("missing guard_skipped is BLIND because coverage was not audited", () => {
    const stamp = freshStamp();
    delete stamp.guard_skipped;

    const decision = readGuardStamp(stamp, now);

    expect(decision.outcome).toBe("BLIND");
    expect(decision.reason).toBe("coverage_unaudited");
    expect(decision.coverage).toBe("unaudited");
  });

  it("explicit skipped subjects are surfaced without pretending coverage is complete", () => {
    const decision = readGuardStamp(
      freshStamp({ guard_skipped: ["static-method:Audit.skipMe"] }),
      now,
    );

    expect(decision.outcome).toBe("OK");
    expect(decision.alerted).toBe(false);
    expect(decision.coverage).toBe("has_exclusions");
    expect(decision.guard_skipped).toEqual(["static-method:Audit.skipMe"]);
  });

  it("a subject rejection remains RED when the liveness control is fresh", () => {
    const decision = readGuardStamp(
      freshStamp({
        guard_fired_at: {
          at: "2026-07-31T11:58:00.000Z",
          input: "known-real-subject-violation",
        },
      }),
      now,
    );

    expect(decision.outcome).toBe("RED");
    expect(decision.alerted).toBe(true);
    expect(decision.reason).toBe("subject_rejected");
  });

  it("NEGATIVE CONTROL: an unconditional alert reader fails the must-allow shape", () => {
    const stamp = freshStamp();
    const correct = readGuardStamp(stamp, now);
    const broken = unconditionalAlertReader(stamp);

    expect(correct.alerted).toBe(false);
    expect(correct.outcome).toBe("OK");

    expect(broken.alerted).toBe(true);
    expect(broken.outcome).toBe("RED");
    expect(broken.alerted).not.toBe(correct.alerted);
  });
});
