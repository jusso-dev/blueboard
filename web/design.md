# Design — blueboard

The locked design system for this app. Every page reads it, and nothing is regenerated per page. To change the system, amend this file first and code second.

## Genre
modern-minimal, technical register (a dark console for SOC analysts on long shifts).

## Macrostructure family
- App pages: **Workbench**, with an N3 side rail, a page header (title, one-line subtitle, controls on the right), and the content area.
  - Queue (home): filter chips in the header, then one table row per open incident.
  - Channel / incident: feed, with an optional thread panel on the right. The incident page puts its summary (hairline-separated blocks, no cards) above the feed.
  - Palette and shortcut list: the only modal dialogs. No motion; focus is trapped and returns on close.
  - Search: filter bar, then results, with an optional thread panel.
  - Approvals: a pending list, or a history table.
  - Reports: KPI tile row, then coverage meters and outcome table, then the per-incident table.
- No marketing or content pages.

## Theme (tokens live in `web/src/styles.css` `@theme`)
| Token | Value | Use |
|---|---|---|
| `paper` / `paper-2` / `paper-3` | oklch 16.5 / 19.5 / 23 % · hue 256 | surfaces; higher = lighter |
| `rule` | oklch 29 % | hairlines between rows and panes |
| `control` | oklch 50 % | input / button boundaries (≥ 3:1) |
| `ink` / `ink-2` / `muted` / `faint` | 94 / 80 / 66 / 60 % | text, all ≥ 4.5:1 on paper |
| `accent` | oklch 68 % 0.17 256 | the one signal: primary button, active rail item, links, focus, meters |
| `critical` / `warning` / `good` | hue 25 / 80 / 155 | status only, always with a word |

## Typography
- Body and UI: Inter Variable (self-hosted via `@fontsource-variable/inter`, no third-party font requests).
- Mono: JetBrains Mono, used only for machine-readout labels (ids, timestamps, tags, KQL).
- No display face. Page titles are 14px semibold, and the only large numbers are stat-tile values (28px).

## Rules every page follows
- Severity, message type and action status are always written out, never colour alone.
- Hairlines, not cards. No shadows, no gradients, no glass.
- Accent covers less than 5% of a view. Most tags are neutral, and only types that change what a reader should do get a tone (incident, action, result, question).
- Silent success: no "Done!" toasts. Errors show inline next to the control that caused them.
- Motion: colour fades of 150 ms and a 1px press on buttons. Nothing else. `prefers-reduced-motion` removes both.
- Numbers in columns use `tnum`.
- Clickable text never wraps. Tables scroll horizontally on narrow screens. Below `md`, the rail becomes a top bar.
