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
    control_rejections_observed: 3,
    control_rejections_expected: 3,
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

describe("control result evidence — the control ran vs the control fired", () => {
  it("MUST-ALLOW: a firing control plus no subject rejection still stays silent", () => {
    const decision = readGuardStamp(
      freshStamp({ control_rejections_observed: 4, control_rejections_expected: 4 }),
      now,
    );

    expect(decision).toMatchObject({
      outcome: "OK",
      alerted: false,
      reason: "fresh_control_no_subject_rejection",
      control_rejections_observed: 4,
      control_rejections_expected: 4,
    });
  });

  it("missing result evidence is BLIND — invocation proved, firing not", () => {
    for (const missing of [
      { control_rejections_observed: null },
      { control_rejections_expected: null },
      {} as Record<string, never>,
    ]) {
      const stamp = freshStamp(missing);
      if (Object.keys(missing).length === 0) {
        delete stamp.control_rejections_observed;
        delete stamp.control_rejections_expected;
      }
      const decision = readGuardStamp(stamp, now);
      expect(decision.outcome).toBe("BLIND");
      expect(decision.reason).toBe("missing_control_result");
    }
  });

  it("a control that caught nothing is BLIND, not OK — the drifted-guard case", () => {
    const decision = readGuardStamp(
      freshStamp({ control_rejections_observed: 0, control_rejections_expected: 3 }),
      now,
    );

    expect(decision.outcome).toBe("BLIND");
    expect(decision.reason).toBe("control_caught_nothing");
    expect(decision.alerted).toBe(true);
  });

  it("a partially dead control is BLIND and reports both numbers", () => {
    const decision = readGuardStamp(
      freshStamp({ control_rejections_observed: 1, control_rejections_expected: 3 }),
      now,
    );

    expect(decision.outcome).toBe("BLIND");
    expect(decision.reason).toBe("control_under_rejected");
    expect(decision.control_rejections_observed).toBe(1);
    expect(decision.control_rejections_expected).toBe(3);
  });

  it("expected === 0 is BLIND: a corpus that trips nothing certifies nothing", () => {
    const decision = readGuardStamp(
      freshStamp({ control_rejections_observed: 0, control_rejections_expected: 0 }),
      now,
    );

    expect(decision.outcome).toBe("BLIND");
    expect(decision.reason).toBe("invalid_control_expected");
  });

  it("non-integer or negative counts are BLIND rather than coerced", () => {
    for (const bad of [
      { control_rejections_observed: -1 },
      { control_rejections_observed: 1.5 },
      { control_rejections_observed: Number.NaN },
      { control_rejections_expected: -2 },
    ]) {
      const decision = readGuardStamp(freshStamp(bad), now);
      expect(decision.outcome).toBe("BLIND");
      expect(decision.reason).toBe("missing_control_result");
    }
  });

  it("a dead control suppresses RED: instrument failure never becomes subject failure", () => {
    const decision = readGuardStamp(
      freshStamp({
        control_rejections_observed: 0,
        control_rejections_expected: 3,
        guard_fired_at: { at: "2026-07-31T11:58:00.000Z", input: "known-bad-subject" },
      }),
      now,
    );

    expect(decision.outcome).toBe("BLIND");
    expect(decision.reason).toBe("control_caught_nothing");
  });

  it("NEGATIVE CONTROL: a freshness-and-hash-only reader passes the stamp this check exists to catch", () => {
    // The reader as it stood before this change: everything up to and including
    // staleness, and nothing about what the control caught. If this assertion
    // ever fails, the new check is not load-bearing and these tests are theatre.
    const freshnessOnlyReader = (stamp: GuardStamp): "OK" | "BLIND" => {
      if (!Array.isArray(stamp.guard_skipped)) return "BLIND";
      if (!stamp.control_corpus_hash) return "BLIND";
      if (!Number.isFinite(stamp.control_max_age_ms) || stamp.control_max_age_ms <= 0) return "BLIND";
      const at = stamp.guard_control_at ? Date.parse(stamp.guard_control_at) : Number.NaN;
      if (!Number.isFinite(at)) return "BLIND";
      const age = now.getTime() - at;
      if (age < 0 || age > stamp.control_max_age_ms) return "BLIND";
      return "OK";
    };

    const drifted = freshStamp({
      control_rejections_observed: 0,
      control_rejections_expected: 3,
    });

    expect(freshnessOnlyReader(drifted)).toBe("OK");
    expect(readGuardStamp(drifted, now).outcome).toBe("BLIND");
  });

  it("NEGATIVE CONTROL: an unconditional-alert reader still fails the must-allow shape", () => {
    const live = freshStamp({ control_rejections_observed: 3, control_rejections_expected: 3 });

    expect(unconditionalAlertReader(live).alerted).toBe(true);
    expect(readGuardStamp(live, now).alerted).toBe(false);
  });
});
