import { useEffect, useRef, useState } from "react";
import { signOut } from "../lib/auth";
import { idleState, lastActivity, recordActivity, type IdleState } from "../lib/idle";
import { Button } from "./ui";

const EVENTS = ["keydown", "pointerdown", "wheel", "touchstart"] as const;

/**
 * Signs the browser out after `minutes` without input (0: off). Shows a warning bar for the last minute with
 * "Stay signed in". Activity is shared across tabs through localStorage.
 */
export function IdleSignOut({ minutes }: { minutes: number }) {
  const local = useRef(Date.now());
  const [state, setState] = useState<IdleState>({ phase: "active", remainingMs: Infinity });

  useEffect(() => {
    if (minutes <= 0) return;
    const store = (() => {
      try {
        return window.localStorage;
      } catch {
        return null;
      }
    })();
    let lastWrite = 0;
    const touch = () => {
      const now = Date.now();
      local.current = now;
      // At most every 5 s, so typing doesn't hammer storage.
      if (store && now - lastWrite > 5000) {
        lastWrite = now;
        recordActivity(store, now);
      }
    };
    touch();
    for (const e of EVENTS) window.addEventListener(e, touch, { passive: true });
    const tick = window.setInterval(() => {
      const s = idleState(Date.now(), lastActivity(store, local.current), minutes);
      setState(s);
      if (s.phase === "expired") {
        window.clearInterval(tick);
        void signOut();
      }
    }, 1000);
    return () => {
      for (const e of EVENTS) window.removeEventListener(e, touch);
      window.clearInterval(tick);
    };
  }, [minutes]);

  if (minutes <= 0 || state.phase !== "warning") return null;
  const secs = Math.ceil(state.remainingMs / 1000);
  return (
    <div role="region" aria-label="Session ending" className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1 border-b border-rule bg-warning-soft/40 px-5 py-2 text-xs">
      <span className="font-semibold text-warning">Session ending:</span>
      <span className="text-ink-2">
        You'll be signed out in <span className="tnum">{secs}</span> s for inactivity ({minutes} minutes).
      </span>
      <Button onClick={() => (local.current = Date.now())}>Stay signed in</Button>
    </div>
  );
}
