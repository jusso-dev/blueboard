import { describe, expect, it } from "vitest";
import { isInteractiveTarget, isTouchLikePointer, LONG_PRESS_MOVE_PX, shouldCancelLongPress } from "../lib/longpress";

describe("message long-press helpers", () => {
  it("triggers only for touch and pen pointers (preserving desktop mouse text selection)", () => {
    expect(isTouchLikePointer("touch")).toBe(true);
    expect(isTouchLikePointer("pen")).toBe(true);
    expect(isTouchLikePointer("mouse")).toBe(false);
    expect(isTouchLikePointer(undefined)).toBe(false);
  });

  it("cancels long-press once finger drifts past the movement threshold", () => {
    expect(shouldCancelLongPress({ x: 100, y: 200 }, { x: 104, y: 205 })).toBe(false);
    expect(shouldCancelLongPress({ x: 100, y: 200 }, { x: 100, y: 200 + LONG_PRESS_MOVE_PX })).toBe(false);
    expect(shouldCancelLongPress({ x: 100, y: 200 }, { x: 100, y: 200 + LONG_PRESS_MOVE_PX + 1 })).toBe(true);
    expect(shouldCancelLongPress({ x: 100, y: 200 }, { x: 108, y: 208 })).toBe(true);
  });

  it("ignores interactive descendants like links and buttons", () => {
    const btnTarget = { closest: (sel: string) => (sel.includes("button") ? {} : null) } as unknown as EventTarget;
    const textTarget = { closest: () => null } as unknown as EventTarget;
    expect(isInteractiveTarget(btnTarget)).toBe(true);
    expect(isInteractiveTarget(textTarget)).toBe(false);
    expect(isInteractiveTarget(null)).toBe(false);
  });
});
