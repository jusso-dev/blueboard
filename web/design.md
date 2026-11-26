# Design — blueboard

The locked design system for this app. Every page reads it, and nothing is regenerated per page. To change the system, amend this file first and code second.

## Genre
modern-minimal, technical register (a dark console for SOC analysts on long shifts).

## Macrostructure family
- App pages: **Workbench**, with an N3 side rail, a page header (title, one-line subtitle, controls on the right), and the content area.
  - Queue (home): filter chips in the header, then one table row per open incident.
  - Channel / incident: a chat feed (Slack "clean" layout, `plans/slack-ui-spec.md`), with an optional thread panel on the right. The incident page puts its summary (hairline-separated blocks, no cards) above the feed; it can be hidden ("Hide summary", remembered) and is capped at 38 % of the viewport so the feed keeps the height.
    - Channel header: `# name` at 20px semibold, the topic in muted 14px. Headers share a 56px minimum height; long titles and topics wrap on phones.
    - Message row: 36px rounded-square avatar with initials on one of six calm tints hashed from the handle (the tint means nothing). Header: name, `AGENT` / `SYSTEM` badge, type tag (omitted for chat), time. The same author and type within 5 minutes groups into body-only rows, with the time in the gutter on hover. Board posts get a neutral tile with a line icon and a muted body, and never group.
    - Day dividers: hairline plus a pill ("Today", "Yesterday", "Tuesday, 25 November", the year only when it isn't this year) that sticks to the top while the day scrolls.
    - Hover or keyboard focus: the row turns `paper-2` and a floating toolbar (3 quick reactions, React, Reply, Copy link) appears top right. Claim, Mark done and Release stay inline under the body.
    - Reactions: a pill row under the body (emoji + count on `paper-3`; the viewer's own in `accent` border on `accent-soft`), then a smiley-plus pill that opens the emoji picker. The picker is a `paper-3` popover like the mention popup: category toolbar, search, a responsive grid (up to 9 columns; 7 at 320px), a `:shortcode:` preview footer. A body of only 1 to 3 emoji renders at 32 px.
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

## Theme (portable tokens in `web/tokens.css`; Tailwind registration in `web/src/styles.css`)
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
- Mono: JetBrains Mono for identifiers, code and KQL only. Ordinary labels, badges and timestamps use Inter; numeric columns use tabular figures.
- Page/channel/thread titles: `text-title`, 20px/28px, semibold. Section titles: 16px/24px, semibold.
- Messages and composer: `text-message`, 15px/22px. Author names: 14px/20px, semibold.
- Navigation, controls, table rows and explanatory prose: `text-ui`, 14px/20px.
- Metadata, timestamps, tags and helper hints: `text-meta`, 12px/16px. No sub-12px meaningful text; small avatar initials are decorative.
- Code: `text-code`, 13px/20px, sized independently of its container.
- Statistics may use 28px; no display face.

## Spacing and controls
- Four-pixel rhythm. Standard controls and navigation rows are 36px high; compact inline actions are 32px. Touch icon targets are 44px.
- Shared header minimum: 56px. Content gutters: 24px desktop, 16px phone. Messages retain a 36px avatar gutter plus 12px gap, including grouped messages.
- Composer follows the same outer gutter as the feed; text and toolbar use 12px inset. Thread and channel headers share title size and alignment.
- Active navigation uses a quiet accent tint. Noninteractive separators stay faint; form boundaries and keyboard focus remain visible.
- Admin destinations are divided rows, with name, explanation and status aligned consistently. No decorative dashboard cards.
- Mobile navigation provides every channel and permitted administration destination through a labelled native destination selector. Queue hides secondary columns before sacrificing the incident title.

## Reference code reviewed (26 November 2026)
- [Rocket.Chat typography tokens](https://github.com/RocketChat/Rocket.Chat/blob/develop/packages/fuselage-tokens/src/typography.json): Inter; named type roles; 14px/20px message body and 12px/16px captions. Blueboard deliberately uses 15px/22px messages for this approved readability pass.
- [Rocket.Chat messages](https://github.com/RocketChat/Rocket.Chat/blob/develop/packages/fuselage/src/components/Message/Messages.styles.scss): fixed 36px avatar gutter, sequential-message alignment, semantic typography and separate header/body treatment.
- [Rocket.Chat composer](https://github.com/RocketChat/Rocket.Chat/blob/develop/packages/ui-composer/src/MessageComposer/MessageComposer.tsx): one grouped composer surface with explicit editing/error state.
- [Mattermost shared header](https://github.com/mattermost/mattermost/blob/master/webapp/channels/src/components/widgets/header/header.scss): consistent 56px frame and restrained title/metadata hierarchy.
- Patterns adapted to existing Blueboard components; no upstream component code copied.

## Rules every page follows
- Severity, message type and action status are always written out, never colour alone.
- Hairlines, not cards. No gradients, no glass. One shadow token (`--shadow-pop`), used only for floating popups (mention picker, message toolbar, jump pill).
- Accent covers less than 5% of a view. Most tags are neutral, and only types that change what a reader should do get a tone (incident, action, result, question).
- Silent success: no "Done!" toasts. Errors show inline next to the control that caused them.
- Motion: colour fades of 150 ms and a 1px press on buttons. Nothing else. `prefers-reduced-motion` removes both.
- Numbers in columns use `tnum`.
- Clickable text never wraps. Tables scroll horizontally on narrow screens. Below `md`, the rail becomes a compact destination selector. Long content wraps within its own column; data tables may scroll inside their own container.

## Verification — 26 November 2026

- Hallmark critique: Philosophy 4, Hierarchy 4, Execution 4, Specificity 5, Restraint 5, Variety 4. App consistency overrides cross-project diversification.
- Local fixture-backed browser checks: channel, thread, queue, admin centre and posture at 320, 375, 414, 768 and desktop widths; no page-level horizontal overflow. Queue columns, emoji grid and mention rows received additional narrow-screen fixes.
- Computed typography: message/composer 15px/22px, page title 20px/28px, code 13px/20px. Visible text contrast checks on the sampled chat/admin views passed WCAG thresholds.
- Interactions checked: message posting, mention insertion, emoji keyboard selection, thread open/Escape/focus return and mobile destination selection. Long channel names wrap.
- `pnpm test`: 138 passed. `pnpm build`: passed; existing bundle-size advisory remains.
- Browser checks used synthetic local data. Live Entra-authenticated workflows and every backend-driven page state were not retested in this visual pass.

## Exports

`tokens.css` is the runtime source of truth. `src/styles.css` registers utilities with
`@theme inline`; its references resolve to the unlayered root values imported from
`tokens.css`. Keep values here in sync when amending the system. Tailwind's built-in
four-pixel spacing utilities remain the spacing scale for existing components.

### tokens.css
```css
/* Blueboard shared design tokens. See design.md for roles and reference sources. */
:root {
  --color-paper: oklch(16.5% 0.012 256);
  --color-paper-2: oklch(19.5% 0.013 256);
  --color-paper-3: oklch(23% 0.015 256);
  --color-rule: oklch(29% 0.016 256);
  --color-rule-strong: oklch(37% 0.018 256);
  --color-control: oklch(50% 0.02 256);
  --color-ink: oklch(94% 0.008 256);
  --color-ink-2: oklch(80% 0.012 256);
  --color-muted: oklch(66% 0.014 256);
  --color-faint: oklch(60% 0.014 256);
  --color-accent: oklch(68% 0.17 256);
  --color-accent-ink: oklch(16% 0.02 256);
  --color-accent-soft: oklch(30% 0.07 256);
  --color-focus: oklch(74% 0.15 256);
  --color-critical: oklch(68% 0.17 25);
  --color-critical-soft: oklch(28% 0.07 25);
  --color-warning: oklch(80% 0.13 80);
  --color-warning-soft: oklch(30% 0.05 80);
  --color-good: oklch(76% 0.13 155);
  --color-good-soft: oklch(28% 0.05 155);
  --color-tint-1: oklch(34% 0.05 256);
  --color-tint-2: oklch(34% 0.05 200);
  --color-tint-3: oklch(34% 0.05 150);
  --color-tint-4: oklch(34% 0.05 85);
  --color-tint-5: oklch(34% 0.05 30);
  --color-tint-6: oklch(34% 0.05 320);
  --shadow-pop: 0 4px 12px oklch(0% 0 0 / 0.35);
  --font-sans: "Inter Variable", ui-sans-serif, system-ui, sans-serif;
  --font-mono: "JetBrains Mono Variable", ui-monospace, "SF Mono", Menlo, monospace;
  --radius-control: 6px;
  --radius-card: 10px;
  --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
  --text-ui: 0.875rem;
  --text-ui--line-height: 1.25rem;
  --text-message: 0.9375rem;
  --text-message--line-height: 1.375rem;
  --text-meta: 0.75rem;
  --text-meta--line-height: 1rem;
  --text-title: 1.25rem;
  --text-title--line-height: 1.75rem;
  --text-code: 0.8125rem;
  --text-code--line-height: 1.25rem;
  --space-unit: 0.25rem;
  --space-xs: 0.5rem;
  --space-sm: 0.75rem;
  --space-md: 1rem;
  --space-lg: 1.5rem;
  --space-xl: 2rem;
  --dur-short: 150ms;
  --rule-hair: 1px;
}
```

### Tailwind v4 registration
```css
@theme inline {
  --color-paper: var(--color-paper);
  --color-paper-2: var(--color-paper-2);
  --color-paper-3: var(--color-paper-3);
  --color-rule: var(--color-rule);
  --color-rule-strong: var(--color-rule-strong);
  --color-control: var(--color-control);
  --color-ink: var(--color-ink);
  --color-ink-2: var(--color-ink-2);
  --color-muted: var(--color-muted);
  --color-faint: var(--color-faint);
  --color-accent: var(--color-accent);
  --color-accent-ink: var(--color-accent-ink);
  --color-accent-soft: var(--color-accent-soft);
  --color-focus: var(--color-focus);
  --color-critical: var(--color-critical);
  --color-critical-soft: var(--color-critical-soft);
  --color-warning: var(--color-warning);
  --color-warning-soft: var(--color-warning-soft);
  --color-good: var(--color-good);
  --color-good-soft: var(--color-good-soft);
  --color-tint-1: var(--color-tint-1);
  --color-tint-2: var(--color-tint-2);
  --color-tint-3: var(--color-tint-3);
  --color-tint-4: var(--color-tint-4);
  --color-tint-5: var(--color-tint-5);
  --color-tint-6: var(--color-tint-6);
  --shadow-pop: var(--shadow-pop);
  --font-sans: var(--font-sans);
  --font-mono: var(--font-mono);
  --radius-control: var(--radius-control);
  --radius-card: var(--radius-card);
  --ease-out: var(--ease-out);
  --text-ui: var(--text-ui);
  --text-ui--line-height: var(--text-ui--line-height);
  --text-message: var(--text-message);
  --text-message--line-height: var(--text-message--line-height);
  --text-meta: var(--text-meta);
  --text-meta--line-height: var(--text-meta--line-height);
  --text-title: var(--text-title);
  --text-title--line-height: var(--text-title--line-height);
  --text-code: var(--text-code);
  --text-code--line-height: var(--text-code--line-height);
}
```

### DTCG tokens.json
```json
{
  "color": {
    "paper": {"$type": "color", "$value": "oklch(16.5% 0.012 256)"},
    "paper-2": {"$type": "color", "$value": "oklch(19.5% 0.013 256)"},
    "paper-3": {"$type": "color", "$value": "oklch(23% 0.015 256)"},
    "rule": {"$type": "color", "$value": "oklch(29% 0.016 256)"},
    "rule-strong": {"$type": "color", "$value": "oklch(37% 0.018 256)"},
    "control": {"$type": "color", "$value": "oklch(50% 0.02 256)"},
    "ink": {"$type": "color", "$value": "oklch(94% 0.008 256)"},
    "ink-2": {"$type": "color", "$value": "oklch(80% 0.012 256)"},
    "muted": {"$type": "color", "$value": "oklch(66% 0.014 256)"},
    "faint": {"$type": "color", "$value": "oklch(60% 0.014 256)"},
    "accent": {"$type": "color", "$value": "oklch(68% 0.17 256)"},
    "accent-ink": {"$type": "color", "$value": "oklch(16% 0.02 256)"},
    "accent-soft": {"$type": "color", "$value": "oklch(30% 0.07 256)"},
    "focus": {"$type": "color", "$value": "oklch(74% 0.15 256)"},
    "critical": {"$type": "color", "$value": "oklch(68% 0.17 25)"},
    "critical-soft": {"$type": "color", "$value": "oklch(28% 0.07 25)"},
    "warning": {"$type": "color", "$value": "oklch(80% 0.13 80)"},
    "warning-soft": {"$type": "color", "$value": "oklch(30% 0.05 80)"},
    "good": {"$type": "color", "$value": "oklch(76% 0.13 155)"},
    "good-soft": {"$type": "color", "$value": "oklch(28% 0.05 155)"},
    "tint-1": {"$type": "color", "$value": "oklch(34% 0.05 256)"},
    "tint-2": {"$type": "color", "$value": "oklch(34% 0.05 200)"},
    "tint-3": {"$type": "color", "$value": "oklch(34% 0.05 150)"},
    "tint-4": {"$type": "color", "$value": "oklch(34% 0.05 85)"},
    "tint-5": {"$type": "color", "$value": "oklch(34% 0.05 30)"},
    "tint-6": {"$type": "color", "$value": "oklch(34% 0.05 320)"}
  },
  "shadow": {
    "pop": {"$type": "shadow", "$value": "0 4px 12px oklch(0% 0 0 / 0.35)"}
  },
  "font": {
    "sans": {"$type": "fontFamily", "$value": "\"Inter Variable\", ui-sans-serif, system-ui, sans-serif"},
    "mono": {"$type": "fontFamily", "$value": "\"JetBrains Mono Variable\", ui-monospace, \"SF Mono\", Menlo, monospace"}
  },
  "radius": {
    "control": {"$type": "dimension", "$value": "6px"},
    "card": {"$type": "dimension", "$value": "10px"}
  },
  "ease": {
    "out": {"$type": "cubicBezier", "$value": [0.16, 1.0, 0.3, 1.0]}
  },
  "text": {
    "ui": {"$type": "dimension", "$value": "0.875rem"},
    "ui--line-height": {"$type": "dimension", "$value": "1.25rem"},
    "message": {"$type": "dimension", "$value": "0.9375rem"},
    "message--line-height": {"$type": "dimension", "$value": "1.375rem"},
    "meta": {"$type": "dimension", "$value": "0.75rem"},
    "meta--line-height": {"$type": "dimension", "$value": "1rem"},
    "title": {"$type": "dimension", "$value": "1.25rem"},
    "title--line-height": {"$type": "dimension", "$value": "1.75rem"},
    "code": {"$type": "dimension", "$value": "0.8125rem"},
    "code--line-height": {"$type": "dimension", "$value": "1.25rem"}
  },
  "space": {
    "unit": {"$type": "dimension", "$value": "0.25rem"},
    "xs": {"$type": "dimension", "$value": "0.5rem"},
    "sm": {"$type": "dimension", "$value": "0.75rem"},
    "md": {"$type": "dimension", "$value": "1rem"},
    "lg": {"$type": "dimension", "$value": "1.5rem"},
    "xl": {"$type": "dimension", "$value": "2rem"}
  },
  "dur": {
    "short": {"$type": "duration", "$value": "150ms"}
  },
  "rule": {
    "hair": {"$type": "dimension", "$value": "1px"}
  }
}
```

### shadcn/ui variables

For current components that consume complete CSS colour values:
```css
:root {
  --background: oklch(16.5% 0.012 256);
  --foreground: oklch(94% 0.008 256);
  --card: oklch(19.5% 0.013 256);
  --card-foreground: oklch(94% 0.008 256);
  --popover: oklch(23% 0.015 256);
  --popover-foreground: oklch(94% 0.008 256);
  --primary: oklch(68% 0.17 256);
  --primary-foreground: oklch(16% 0.02 256);
  --secondary: oklch(23% 0.015 256);
  --secondary-foreground: oklch(80% 0.012 256);
  --muted: oklch(23% 0.015 256);
  --muted-foreground: oklch(66% 0.014 256);
  --accent: oklch(30% 0.07 256);
  --accent-foreground: oklch(94% 0.008 256);
  --destructive: oklch(68% 0.17 25);
  --border: oklch(29% 0.016 256);
  --input: oklch(50% 0.02 256);
  --ring: oklch(74% 0.15 256);
  --radius: 6px;
}
```
