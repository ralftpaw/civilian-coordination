/**
 * Liveness-of-guard: plane 3 of the abort-receipt design.
 *
 * The claim this implements
 * -------------------------
 * A failure notifier that fires from OUTSIDE the audited process is necessary
 * and **not sufficient**. It also has to be shown *not* to fire on a healthy
 * run — and that is the control people skip, because the three obvious tests
 * all pass without it.
 *
 * A notifier that alerts unconditionally on every run passes "it delivers",
 * "it reports RED" and "it reports BLIND". Only the must-allow control
 * separates a guard from a thing that screams on every path. The test file
 * beside this one includes that broken notifier explicitly and proves the
 * suite catches it, because a control nobody can see is a control the next
 * contributor deletes.
 *
 * Typed outcomes
 * --------------
 * `RED` (checked, found a problem) and `BLIND` (could not check) must never
 * collapse into one "failed" state. They license different actions: only RED
 * is a statement about the subject. A credential lapse, an unreachable
 * instrument or a timeout is a statement about *us*, and reading it as a clean
 * bill of health is how a monitoring gap becomes a settlement decision.
 */

/** What a single audited run concluded. */
export type Outcome = "CLEAN" | "RED" | "BLIND";

/**
 * Exit-code contract for an audited unit.
 *
 * 0 -> CLEAN  ran, checked, found nothing
 * 1 -> RED    ran, checked, found a real problem
 * 2 -> BLIND  could not check (credential lapse, instrument unreachable, timeout)
 *
 * Anything else is BLIND, deliberately: an unrecognised exit code means the
 * unit failed in a way we have no vocabulary for, and the safe reading of "I
 * do not know what happened" is *not* "nothing happened". A process killed by
 * a signal never runs its own handler and lands here.
 */
export function classify(exitCode: number | null, signal?: string | null): Outcome {
  if (signal) return "BLIND";
  if (exitCode === 0) return "CLEAN";
  if (exitCode === 1) return "RED";
  return "BLIND";
}

/** A notification emitted by the supervisor — never by the audited process. */
export interface Alert {
  unit: string;
  outcome: Exclude<Outcome, "CLEAN">;
  exitCode: number | null;
  signal?: string | null;
}

export interface Notifier {
  /**
   * Prove the channel works at all, independently of any audit.
   *
   * Without this, "no alert arrived" is ambiguous between *nothing was wrong*
   * and *the notifier is broken*, which is the ambiguity the whole design
   * exists to remove.
   */
  selftest(): Promise<boolean>;
  send(alert: Alert): Promise<void>;
}

/** Somewhere a clean run records that it happened, so silence becomes checkable. */
export interface StampWriter {
  write(unit: string): Promise<void>;
}

export interface RunResult {
  outcome: Outcome;
  alerted: boolean;
  stamped: boolean;
}

/**
 * Supervise one run of an audited unit.
 *
 * The notifier is invoked **here**, by the supervisor, from the exit status —
 * not by the audited process. An in-process handler cannot report a fault that
 * stopped it reaching its own code: an OOM, a timeout, or a signal. That is
 * the whole reason this function exists rather than a `try/catch` inside the
 * unit.
 *
 * @param exitCode exit code observed by the supervisor, or `null` if signalled
 * @param signal   signal name if the process was killed, else null/undefined
 */
export async function superviseRun(
  unit: string,
  exitCode: number | null,
  signal: string | null | undefined,
  notifier: Notifier,
  stamps: StampWriter,
): Promise<RunResult> {
  const outcome = classify(exitCode, signal);

  if (outcome === "CLEAN") {
    // Must-allow: a healthy run is SILENT. The stamp is the only trace, and it
    // exists so that "nothing was sent" can later be distinguished from "the
    // guard never ran" by something else reading it.
    await stamps.write(unit);
    return { outcome, alerted: false, stamped: true };
  }

  // BLIND must NOT leave a success stamp. A stamp on an unchecked run is a
  // record that says "verified" about a run that verified nothing — worse
  // than no record, because a later reader treats it as coverage.
  await notifier.send({ unit, outcome, exitCode, signal });
  return { outcome, alerted: true, stamped: false };
}
