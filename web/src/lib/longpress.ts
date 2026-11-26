/**
 * Pure helpers for Slack-style touch long-press detection on message rows.
 * Kept DOM-minimal so thresholds and target filtering are directly unit-testable.
 */

export const LONG_PRESS_MS = 420;
export const LONG_PRESS_MOVE_PX = 10;
export const LONG_PRESS_SUPPRESS_MS = 600;

const INTERACTIVE_SELECTOR = 'a, button, input, select, textarea, summary, [role="button"], [role="link"]';

/** Only touch and pen pointers trigger long-press so desktop mouse text selection is never disrupted. */
export function isTouchLikePointer(pointerType: string | undefined): boolean {
  return pointerType === "touch" || pointerType === "pen";
}

/** Returns true if a finger moved far enough to be a scroll or swipe rather than a stationary hold. */
export function shouldCancelLongPress(start: { x: number; y: number }, current: { x: number; y: number }): boolean {
  return Math.hypot(current.x - start.x, current.y - start.y) > LONG_PRESS_MOVE_PX;
}

/** Don't hijack long-presses started on interactive controls (links, buttons, inputs). */
export function isInteractiveTarget(target: EventTarget | null): boolean {
  if (!target || typeof target !== "object") return false;
  const el = target as { closest?: (selector: string) => unknown };
  return typeof el.closest === "function" && el.closest(INTERACTIVE_SELECTOR) !== null;
}
