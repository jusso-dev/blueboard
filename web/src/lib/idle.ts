/**
 * Idle sign-out (SESSION_IDLE_MINUTES, from GET /status). Any keyboard, pointer, wheel or touch input in any tab of the
 * board resets the clock; tabs share the last-activity time through localStorage so a second tab doesn't sign the
 * first out. A warning shows for the final minute. Signing out clears MSAL's session-storage tokens and ends the Entra
 * session for this app (logoutRedirect).
 */
export const ACTIVITY_KEY = "bb_last_activity";
export const WARN_MS = 60_000;

export type IdleState = { phase: "active" | "warning" | "expired"; remainingMs: number };

/** Pure: where the session stands, given the idle limit and the last activity time. */
export function idleState(now: number, lastActivity: number, idleMinutes: number): IdleState {
  if (idleMinutes <= 0) return { phase: "active", remainingMs: Number.POSITIVE_INFINITY };
  const remainingMs = lastActivity + idleMinutes * 60_000 - now;
  if (remainingMs <= 0) return { phase: "expired", remainingMs: 0 };
  return { phase: remainingMs <= WARN_MS ? "warning" : "active", remainingMs };
}

/** The latest activity seen by any tab (localStorage), or by this one if storage is unavailable. */
export function lastActivity(storage: Pick<Storage, "getItem"> | null, fallback: number): number {
  try {
    const v = Number(storage?.getItem(ACTIVITY_KEY));
    return Number.isFinite(v) && v > fallback ? v : fallback;
  } catch {
    return fallback;
  }
}

/** Storage may exist but refuse writes (privacy settings or quota). Local expiry must still work. */
export function recordActivity(storage: Pick<Storage, "setItem"> | null, now: number): void {
  try {
    storage?.setItem(ACTIVITY_KEY, String(now));
  } catch {
    // The calling tab keeps its own timestamp; only cross-tab sharing is unavailable.
  }
}
