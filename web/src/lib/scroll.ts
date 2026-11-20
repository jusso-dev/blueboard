/** Feed auto-scroll rules, kept free of React and the DOM so they can be unit-tested. */

/** Within this many pixels of the bottom counts as "reading the newest messages". */
export const NEAR_BOTTOM_PX = 120;

export function isNearBottom(el: { scrollHeight: number; scrollTop: number; clientHeight: number }, px = NEAR_BOTTOM_PX): boolean {
  return el.scrollHeight - el.scrollTop - el.clientHeight <= px;
}

/**
 * Scroll to the end on the first load, or when a newer message arrived and the reader was already near the bottom.
 * A poll that returns the same newest message never moves the view.
 */
export function shouldFollow(lastSeen: string | undefined, newest: string | undefined, nearBottom: boolean): boolean {
  if (newest === undefined || newest === lastSeen) return false;
  return lastSeen === undefined || nearBottom;
}
