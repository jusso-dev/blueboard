/** Inline line icons: 16 px, 1.5 stroke, currentColor. Decorative unless given a label by the caller. */
import type { ReactNode } from "react";

function Svg({ children, size = 16, className }: { children: ReactNode; size?: number; className?: string }) {
  return (
    <svg
      aria-hidden
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      {children}
    </svg>
  );
}

type P = { size?: number; className?: string };

export const IconReply = (p: P) => (
  <Svg {...p}>
    <path d="M2.5 4.5a2 2 0 0 1 2-2h7a2 2 0 0 1 2 2v4.5a2 2 0 0 1-2 2H7l-3 2.5v-2.5h0a2 2 0 0 1-1.5-2z" />
    <path d="M5.5 5.75h5M5.5 8h3" />
  </Svg>
);

export const IconLink = (p: P) => (
  <Svg {...p}>
    <path d="M6.75 9.25a2.75 2.75 0 0 0 3.9 0l2-2a2.75 2.75 0 0 0-3.9-3.9l-.6.6" />
    <path d="M9.25 6.75a2.75 2.75 0 0 0-3.9 0l-2 2a2.75 2.75 0 0 0 3.9 3.9l.6-.6" />
  </Svg>
);

export const IconClose = (p: P) => (
  <Svg {...p}>
    <path d="M4 4l8 8M12 4l-8 8" />
  </Svg>
);

export const IconBack = (p: P) => (
  <Svg {...p}>
    <path d="M13 8H3.5M7.5 4 3.5 8l4 4" />
  </Svg>
);

export const IconAt = (p: P) => (
  <Svg {...p}>
    <circle cx="8" cy="8" r="2.5" />
    <path d="M10.5 8v1a1.75 1.75 0 0 0 3.5 0V8a6 6 0 1 0-2.4 4.8" />
  </Svg>
);

export const IconSend = (p: P) => (
  <Svg {...p}>
    <path d="M2.5 8 13.5 2.5 11 13.5 7.5 9 2.5 8z" />
    <path d="M7.5 9 13.5 2.5" />
  </Svg>
);

export const IconChevronRight = (p: P) => (
  <Svg {...p}>
    <path d="m6 3.5 4.5 4.5L6 12.5" />
  </Svg>
);

export const IconArrowDown = (p: P) => (
  <Svg {...p}>
    <path d="M8 3v10M4 9l4 4 4-4" />
  </Svg>
);

/** The board's own posts (ingest poller, broker): a small stack of layers. */
export const IconBoard = (p: P) => (
  <Svg {...p}>
    <path d="M8 2.5 13.5 5.25 8 8 2.5 5.25 8 2.5z" />
    <path d="m2.5 8 5.5 2.75L13.5 8M2.5 10.75 8 13.5l5.5-2.75" />
  </Svg>
);

export const IconCheck = (p: P) => (
  <Svg {...p}>
    <path d="m3.5 8.5 3 3 6-7" />
  </Svg>
);

/** Add reaction: a smiley with a small plus (Slack's "React" affordance). */
export const IconSmilePlus = (p: P) => (
  <Svg {...p}>
    <path d="M13.4 7.2A5.5 5.5 0 1 1 8.8 2.56" />
    <path d="M5.75 9.5a2.75 2.75 0 0 0 4.5 0" />
    <path d="M6 6.25h.01M9.5 6.25h.01" />
    <path d="M12.5 1.5v4M10.5 3.5h4" />
  </Svg>
);

export const IconSmile = (p: P) => (
  <Svg {...p}>
    <circle cx="8" cy="8" r="5.5" />
    <path d="M5.75 9.5a2.75 2.75 0 0 0 4.5 0M6 6.25h.01M10 6.25h.01" />
  </Svg>
);

export const IconClock = (p: P) => (
  <Svg {...p}>
    <circle cx="8" cy="8" r="5.5" />
    <path d="M8 5v3l2 1.5" />
  </Svg>
);

export const IconLeaf = (p: P) => (
  <Svg {...p}>
    <path d="M3 13c0-6 3.5-9.5 10-10-.5 6.5-4 10-10 10z" />
    <path d="M3 13 9 7" />
  </Svg>
);

export const IconFood = (p: P) => (
  <Svg {...p}>
    <path d="M2.5 7.5h11a5.5 5.5 0 0 1-11 0z" />
    <path d="M6 5.5c0-1 .75-1 .75-2M9.25 5.5c0-1 .75-1 .75-2" />
  </Svg>
);

export const IconBall = (p: P) => (
  <Svg {...p}>
    <circle cx="8" cy="8" r="5.5" />
    <path d="M2.5 8h11M8 2.5c-2 2-2 9 0 11M8 2.5c2 2 2 9 0 11" />
  </Svg>
);

export const IconPlane = (p: P) => (
  <Svg {...p}>
    <path d="M7 9 2.5 7.5l1-1L8 7l3-3.25a1.25 1.25 0 0 1 1.75 1.75L9.5 8.5l.5 4.5-1 1L7.5 9.5 5 12v1.5l-1 .5-.5-1.75L1.75 11.5l.5-1H4z" />
  </Svg>
);

export const IconBulb = (p: P) => (
  <Svg {...p}>
    <path d="M6 11.5h4M6.5 13.5h3M8 2a4 4 0 0 0-2.25 7.3c.4.3.75.8.75 1.2v1h3v-1c0-.4.35-.9.75-1.2A4 4 0 0 0 8 2z" />
  </Svg>
);

export const IconSymbols = (p: P) => (
  <Svg {...p}>
    <path d="M8 13.5S2.5 10.25 2.5 6.5A2.75 2.75 0 0 1 8 5a2.75 2.75 0 0 1 5.5 1.5c0 3.75-5.5 7-5.5 7z" />
  </Svg>
);

export const IconFlag = (p: P) => (
  <Svg {...p}>
    <path d="M3.5 14V2.5M3.5 3h8l-1.5 3 1.5 3h-8" />
  </Svg>
);

export const IconSearch = (p: P) => (
  <Svg {...p}>
    <circle cx="7" cy="7" r="4.5" />
    <path d="m10.5 10.5 3 3" />
  </Svg>
);

export const IconBell = (p: P) => (
  <Svg {...p}>
    <path d="M4 11.5V7a4 4 0 0 1 8 0v4.5l1 1H3z" />
    <path d="M6.5 13.5a1.5 1.5 0 0 0 3 0" />
  </Svg>
);
