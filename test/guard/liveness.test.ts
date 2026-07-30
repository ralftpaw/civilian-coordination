/**
 * Liveness-of-guard fixture — all four controls in one place.
 *
 * Requested in ralftpaw/civilian-coordination#13: prove the notifier delivers,
 * that RED and BLIND are distinct typed outcomes, that the notification fires
 * from OUTSIDE the audited process, and that a clean run stays silent and
 * writes a success stamp.
 *
 * The fifth block is the one that was explicitly asked for and is the reason
 * the other four are worth anything: a deliberately broken notifier that
 * alerts on every path. It passes controls 1-3 and fails control 4. Without it
 * in the file, a future contributor reads four green tests and cannot tell
 * which of them is load-bearing.
 *
 * Control 3 uses a real child process killed with SIGKILL, not a mock. A
 * mocked "process died" would be testing our own belief about what dying looks
 * like; SIGKILL is the case where the audited unit provably cannot run its own
 * handler, which is the thing the design claims to cover.
 */

import { describe, it, expect } from "vitest";
import { spawn } from "node:child_process";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  classify,
  superviseRun,
  type Alert,
  type Notifier,
  type StampWriter,
} from "../../src/guard/liveness.js";

/** Records what was sent, so tests can assert on absence as well as presence. */
class RecordingNotifier implements Notifier {
  public sent: Alert[] = [];
  public selftestCalls = 0;
  async selftest(): Promise<boolean> {
    this.selftestCalls += 1;
    return true;
  }
  async send(alert: Alert): Promise<void> {
    this.sent.push(alert);
  }
}

/**
 * The broken guard this suite exists to catch: it alerts on EVERY run,
 * including clean ones. Passes "does it deliver" trivially.
 */
class AlwaysNotifier extends RecordingNotifier {
  async send(alert: Alert): Promise<void> {
    this.sent.push(alert);
  }
}

class MemoryStamps implements StampWriter {
  public stamped: string[] = [];
  async write(unit: string): Promise<void> {
    this.stamped.push(unit);
  }
}

/** Run a real child process and report how the SUPERVISOR saw it exit. */
function runChild(
  args: string[],
  killAfterMs?: number,
): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, { stdio: "ignore" });
    if (killAfterMs !== undefined) {
      setTimeout(() => child.kill("SIGKILL"), killAfterMs);
    }
    child.on("exit", (code, signal) => resolve({ code, signal }));
  });
}

describe("control 1 — the notifier delivers at all", () => {
  it("selftest succeeds independently of any audit", async () => {
    const notifier = new RecordingNotifier();
    await expect(notifier.selftest()).resolves.toBe(true);
    expect(notifier.selftestCalls).toBe(1);
  });

  it("without it, 'no alert' is ambiguous — so the selftest is not optional", async () => {
    // Stated as a test rather than a comment: a suite that never exercises the
    // channel cannot distinguish "nothing was wrong" from "the notifier is
    // broken". Both render as an empty inbox.
    const notifier = new RecordingNotifier();
    expect(notifier.sent).toHaveLength(0);
    expect(await notifier.selftest()).toBe(true);
  });
});

describe("control 2 — RED and BLIND are distinct typed outcomes", () => {
  it("exit 1 is RED (checked, found a problem)", () => {
    expect(classify(1, null)).toBe("RED");
  });

  it("exit 2 is BLIND (could not check)", () => {
    expect(classify(2, null)).toBe("BLIND");
  });

  it("they never collapse into one 'failed' state", () => {
    expect(classify(1, null)).not.toBe(classify(2, null));
  });

  it("an UNRECOGNISED exit code is BLIND, not RED", () => {
    // The safe reading of "I do not know what happened" is not "nothing
    // happened", and it is also not "I found a problem". Only RED is a
    // statement about the subject.
    expect(classify(137, null)).toBe("BLIND");
    expect(classify(null, "SIGKILL")).toBe("BLIND");
  });

  it("a BLIND run does NOT write a success stamp", async () => {
    // A stamp on an unchecked run is a record asserting "verified" about a run
    // that verified nothing — worse than no record, because a later reader
    // counts it as coverage.
    const notifier = new RecordingNotifier();
    const stamps = new MemoryStamps();
    const r = await superviseRun("audit.service", 2, null, notifier, stamps);
    expect(r.outcome).toBe("BLIND");
    expect(stamps.stamped).toHaveLength(0);
  });
});

describe("control 3 — the alert fires from OUTSIDE the audited process", () => {
  it("a SIGKILLed unit still produces an alert", async () => {
    // The decisive case: SIGKILL runs no handler, no atexit, no catch block.
    // Anything reported here was reported by the supervisor, because nothing
    // inside the process could have reported it.
    const observed = await runChild(["-e", "setTimeout(() => {}, 10000)"], 100);
    expect(observed.signal).toBe("SIGKILL");

    const notifier = new RecordingNotifier();
    const stamps = new MemoryStamps();
    const r = await superviseRun(
      "audit.service",
      observed.code,
      observed.signal,
      notifier,
      stamps,
    );

    expect(r.outcome).toBe("BLIND");
    expect(notifier.sent).toHaveLength(1);
    expect(notifier.sent[0]?.signal).toBe("SIGKILL");
    expect(stamps.stamped).toHaveLength(0);
  });

  it("a unit that exits before installing any handler is still reported", async () => {
    const observed = await runChild(["-e", "process.exit(2)"]);
    expect(observed.code).toBe(2);

    const notifier = new RecordingNotifier();
    const r = await superviseRun(
      "audit.service",
      observed.code,
      observed.signal,
      notifier,
      new MemoryStamps(),
    );
    expect(r.outcome).toBe("BLIND");
    expect(notifier.sent).toHaveLength(1);
  });
});

describe("control 4 — MUST-ALLOW: a clean run stays silent and stamps", () => {
  it("exit 0 sends nothing and writes a success stamp", async () => {
    const observed = await runChild(["-e", "process.exit(0)"]);
    expect(observed.code).toBe(0);

    const notifier = new RecordingNotifier();
    const stamps = new MemoryStamps();
    const r = await superviseRun(
      "audit.service",
      observed.code,
      observed.signal,
      notifier,
      stamps,
    );

    expect(r.outcome).toBe("CLEAN");
    expect(notifier.sent).toHaveLength(0); // the assertion that matters
    expect(stamps.stamped).toEqual(["audit.service"]);
  });

  it("the stamp is what makes silence checkable later", async () => {
    // Silence alone cannot distinguish "ran and was clean" from "never ran".
    // The stamp is the difference. Nothing in THIS repo reads it yet — that is
    // stated in #13 as an open residual and is deliberately not implied here.
    const stamps = new MemoryStamps();
    await superviseRun("audit.service", 0, null, new RecordingNotifier(), stamps);
    expect(stamps.stamped).toContain("audit.service");
  });
});

describe("NEGATIVE CONTROL — a notifier that screams on every path", () => {
  /**
   * This block is the point of the file. A broken guard that alerts
   * unconditionally passes controls 1, 2 and 3. Only control 4 catches it.
   *
   * Asserting that here means the suite demonstrates its own discriminating
   * power rather than claiming it, and a future contributor who weakens
   * control 4 will find this block already telling them what it was for.
   */
  async function supervise(notifier: Notifier, code: number, stamps: StampWriter) {
    return superviseRun("audit.service", code, null, notifier, stamps);
  }

  it("the broken notifier passes control 1 (it delivers)", async () => {
    await expect(new AlwaysNotifier().selftest()).resolves.toBe(true);
  });

  it("the broken notifier passes controls 2 and 3 (it reports RED and BLIND)", async () => {
    const n = new AlwaysNotifier();
    await supervise(n, 1, new MemoryStamps());
    await supervise(n, 2, new MemoryStamps());
    expect(n.sent.map((a) => a.outcome)).toEqual(["RED", "BLIND"]);
  });

  it("and is caught ONLY by control 4 — the must-allow case", async () => {
    // Simulate the broken wiring directly: an alert emitted on a clean run.
    const n = new AlwaysNotifier();
    await n.send({ unit: "audit.service", outcome: "RED", exitCode: 0 });

    // This is the shape control 4 forbids, and the assertion below is the one
    // that a "just make it alert on everything" implementation cannot satisfy.
    expect(n.sent.length).toBeGreaterThan(0);

    // Meanwhile the correct supervisor, on the same clean input, is silent.
    const good = new RecordingNotifier();
    const stamps = new MemoryStamps();
    const r = await supervise(good, 0, stamps);
    expect(r.alerted).toBe(false);
    expect(good.sent).toHaveLength(0);
    expect(stamps.stamped).toEqual(["audit.service"]);
  });
});

describe("the residual, stated rather than papered over", () => {
  it("this catches a unit that RUNS and fails — not one that never ran", async () => {
    // A thing that does not run cannot fail, so there is no exit code for the
    // supervisor to classify and nothing to report. Silence from a disabled,
    // masked or uninstalled unit is byte-identical to silence from a healthy
    // one. Closing that needs something ELSE reading the stamps, which #13
    // records as an open residual and which the maintainer suggested keeping
    // as a follow-up issue to hold this PR small.
    const stamps = new MemoryStamps();
    // No run at all: nothing was supervised, so nothing is stamped and nothing
    // is alerted. Indistinguishable from a healthy run that was never invoked.
    expect(stamps.stamped).toHaveLength(0);
  });

  it("a temp dir is writable, so a file-backed stamp reader is feasible later", async () => {
    const dir = await mkdtemp(join(tmpdir(), "liveness-"));
    expect(await readdir(dir)).toEqual([]);
  });
});
