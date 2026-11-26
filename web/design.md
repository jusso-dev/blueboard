# Design — blueboard

The locked design system for this app. Every page reads it, and nothing is regenerated per page. To change the system, amend this file first and code second.

## Genre
modern-minimal, technical register (a dark console for SOC analysts on long shifts).

## Macrostructure family
- App pages: **Workbench**, with an N3 side rail, a page header (title, one-line subtitle, controls on the right), and the content area.
  - Queue (home): filter chips in the header, then one table row per open incident.
  - Channel / incident: a chat feed (Slack "clean" layout, `plans/slack-ui-spec.md`), with an optional thread panel on the right. The incident page puts its summary (hairline-separated blocks, no cards) above the feed; it can be hidden ("Hide summary", remembered) and is capped at 38 % of the viewport so the feed keeps the height.
    - Channel header: `# name` at 18px semibold, the topic inline in muted 13px, truncated.
    - Message row: 36px rounded-square avatar with initials on one of six calm tints hashed from the handle (the tint means nothing). Header: name, `AGENT` / `SYSTEM` badge, type tag (omitted for chat), time. The same author and type within 5 minutes groups into body-only rows, with the time in the gutter on hover. Board posts get a neutral tile with a line icon and a muted body, and never group.
    - Day dividers: hairline plus a pill ("Today", "Yesterday", "Tuesday, 25 November", the year only when it isn't this year) that sticks to the top while the day scrolls.
    - Hover or keyboard focus: the row turns `paper-2` and a floating toolbar (3 quick reactions, React, Reply, Copy link) appears top right. Claim, Mark done and Release stay inline under the body.
    - Reactions: a pill row under the body (emoji + count on `paper-3`; the viewer's own in `accent` border on `accent-soft`), then a smiley-plus pill that opens the emoji picker. The picker is a `paper-3` popover like the mention popup: category toolbar, search, a 9-column grid, a `:shortcode:` preview footer. A body of only 1 to 3 emoji renders at 32 px.
    - `action_request` rows: an approver sees the live action status with Approve and Deny (and the confirm-target field) inline; the same form as the Approvals page.
    - Replies never show inline. A root gets a summary row: up to 4 repliers' 24px avatars, "N replies" in accent, "Last reply …" (which becomes "View thread" on hover). In incident feeds a reply whose root isn't loaded shows with a "replied to a thread" link.
    - Bodies over about 24 lines clamp with "Show more". Prose caps at 72ch, code blocks scroll sideways, long tokens wrap.
    - Mentions: `@handle` chips in `accent-soft`. The viewer's own handle is a solid `accent` chip, and the row gets a 2px accent left rule plus "mentions you" for screen readers.
    - Thread panel: "Thread #channel", the root, a "N replies" hairline, the replies, then the composer ("Reply…"). It docks at 420px (drag or arrow keys resize it between 320px and 50vw, and the width is remembered). If the channel would drop below 480px, it becomes an overlay sheet (a dialog with a focus trap and Esc). Below 640px it goes full screen with a back arrow.
    - Composer: a rounded box on `paper-2` that grows to 40 % of the viewport. The bottom row holds the message type, an `@` button and an icon-only Send in accent. The draft is kept per conversation for the session. Typing `@` opens the mention picker (people and agents, best match first): an APG combobox with `paper-3` rows, the selected row in `accent-soft`, and a key-hint footer. `:` plus two characters opens the same popup for emoji shortcodes; an emoji button sits beside `@`. Under the box, a 12px muted typing line ("Enrichment agent is typing…", three dots that hold still under reduced motion) keeps its height whether or not anyone is typing.
    - "N new messages" / "Jump to recent" pill above the composer when you're more than a viewport up.
  - Palette and shortcut list: the only modal dialogs. No motion; focus is trapped and returns on close.
  - Search: filter bar, then results, with an optional thread panel.
  - Approvals: a pending list, or a history table.
  - Reports: KPI tile row, then coverage meters and outcome table, then the per-incident table.
  - Setup: one row per check (status tag in words, name, detail, mono detail lines, "How to fix"), then the test-notification section.
  - Participants: the Broker section (state tag, pause/resume with a required reason inline), then the participants table.
- Status banner: one hairline-separated line per condition above the page header, label in the status colour plus a sentence. Critical (paused, policy missing) and warning (dry run, held actions, default policy) only.
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
- Hairlines, not cards. No gradients, no glass. One shadow token (`--shadow-pop`), used only for floating popups (mention picker, message toolbar, jump pill).
- Accent covers less than 5% of a view. Most tags are neutral, and only types that change what a reader should do get a tone (incident, action, result, question).
- Silent success: no "Done!" toasts. Errors show inline next to the control that caused them.
- Motion: colour fades of 150 ms and a 1px press on buttons. Nothing else. `prefers-reduced-motion` removes both.
- Numbers in columns use `tnum`.
- Clickable text never wraps. Tables scroll horizontally on narrow screens. Below `md`, the rail becomes a top bar.
