# Slack-style chat UI spec for blueboard

Scope: rebuild the channel, thread and composer views in `web/src` (React + Tailwind v4) to follow Slack's desktop/web patterns, using our own dark tokens. Copy no Slack branding, logos, fonts or colours. Slack values below are for proportion only. The **blueboard** lines say what to build.

## 0. How to read the numbers

- **Primary source:** a private screenshot set of the Slack web app (not in this repo) (745 PNGs, Slack web app, July 2024, light theme, with one dark frame). Frame numbers are listed in §11.
- **Scale:** the PNGs are 1920 px wide but are **not 1x**. Slack's known 36 px avatar measures 46 px, and the body line pitch measures 28 px against Slack's 22 px. Both give a factor of **1.28**. Every **(M)** value below is the screenshot pixel value ÷ 1.28, rounded to whole CSS px. Expect ±1 px.
- **Tags:** **(M)** measured from frames · **(S)** stated in a cited source · **(I)** inferred or recommended (not visible in frames or docs).
- Timing and motion cannot be measured from still frames. Every duration here is (S) or (I).

## 1. Message list

Sources: frames 205, 207, 225, 547, 555; https://slack.com/help/articles/213893898-Change-how-messages-are-displayed ; https://github.com/arugula-salad/illogical/issues/337 ; https://oh-my-design.kr/design-systems/slack (third-party teardown, unverified)

### 1.1 Row geometry (clean/default theme)
- Pane edge to avatar: **20 px** left padding (M, 551−526 = 25 → 20). Right padding: 20 px (I, matches left).
- Avatar: **36 × 36**, rounded square, radius **4–6 px** (M size, S radius 4 px). Top aligned with the name line.
- Avatar to text gap: **8 px** (M). The text column starts **64 px** from the pane edge (M: 82 → 64). That 64 px is the **gutter** that grouped rows use too.
- Header line: **display name** 15 px bold, ink colour · 8 px gap · **timestamp** 12 px regular, muted ("12:53 PM") (M sizes ±1). The timestamp is a link to the message permalink, with the full date in its tooltip (S, Slack behaviour).
- Body: **15 px / 22 px** line height (M pitch 28 → 22; S 15/22).
- Pitch of one message (header plus one body line): **52 px** (M: avatars at y 200 → 266). Split this as 8 px top padding + 18 px header + 22 px body + 4 px bottom (I). Slack's component padding is `8px 20px` (S teardown).
- Max text width: none. Body text runs to the right padding (M, frame 225 line runs to x≈1700 of 1914). Attachments cap at about **420 px** wide (M: PDF card 607→1147 = 540 → 422).
- **blueboard:** keep full-width text but cap prose at `max-w-[72ch]` for readability. Our board messages are long and analytical, unlike Slack chat. (I)

### 1.2 Grouping (consecutive messages, same author)
- Rule: a message joins the previous row when it has the **same author**, falls **within 5 minutes**, is **not a channel event**, has **no day divider between**, and the previous message is not the thread root of a new thread (S issue #337; I for the last two).
- A grouped row is body-only. It has no avatar and no name. Padding is **2 px top / 2 px bottom** (I), so pitch is about 26 px per line.
- Gutter on a grouped row: on hover, the time **without AM/PM** ("2:54") shows right-aligned in the 64 px gutter, 12 px muted, aligned to the body baseline (S/I).
- Observed in frame 138: three "Sam Lee 3:48 PM" **channel-event** messages each keep a full header. **Event/system messages never group.** (M)
- **blueboard:** also break a group when `type` changes (for example `chat` → `finding`). The type tag lives in the header (§10), so a type change needs a header row. (I)

### 1.3 Day dividers
- Full-width 1 px hairline across the whole pane (edge to edge, no padding) with a centred **pill** (M, frames 172, 205).
- Pill: about **30 px tall**, padding 0 16 px, fully rounded, 1 px border, same background as the pane, 13 px **semibold** label, trailing chevron (the chevron opens a "jump to date" menu) (M, chevron S).
- Labels: **"Today"**, **"Yesterday"**, then **"Thursday, June 13th"** (weekday + month + ordinal) (M). Slack adds the year only for other years (I). **blueboard (AU):** "Tuesday, 25 November" with no ordinal, and add the year when it is not the current year.
- **Sticky:** while a day's messages scroll, the pill floats at the top of the list, **about 8 px below the header hairline**, and its line is hidden (M, frames 207, 223, 225 show the pill alone at y≈184 under the header). Implement with `position: sticky; top: 8px` on the pill, inside a per-day section wrapper, so the next day's pill pushes the previous one out. (I)
- Vertical space: about 16 px above the line and 8 px below the pill (M ±2).

### 1.4 "New" unread divider
- A 1 px line in Slack's alert colour across the full width, with a right-aligned label **"New"** at 13 px semibold in the same colour (M, frames 205, 351).
- When it falls on a day boundary, the day pill sits on the New line and the line runs either side of the pill (M, frame 205).
- It sits above the first unread message. It **stays put for the session** even after the channel is marked read, as a bookmark for that visit (S https://slack.green/en/blog/slack-mark-as-unread).
- Threads get their own New line inside the thread view (M, frame 351).
- **blueboard:** draw the line in `accent`, not red. Red is reserved for `critical`. Keep the word "New" so meaning never depends on colour.

### 1.5 Hover state
- Row background goes from white to **#f8f8f8** across the full pane width, edge to edge (M, frame 207, band 531→1909). That is one step lighter or darker than the surface.
- **blueboard:** `hover:bg-paper-2` on the row, with `transition-colors duration-150`. Apply the same style on `:focus-within` and on the keyboard-focused message.

### 1.6 Floating hover toolbar
- Position: **top-right of the hovered row**, **16 px** from the pane's right edge (M). It overlaps upward so its top sits **about 20 px above the row's top edge** (M: toolbar top 531, row top 556). It covers the previous row's last line, which is intended.
- Size: about **258 × 36 px** (M), 1 px border, radius **6–8 px** (S 8), small drop shadow (S `0 4px 12px rgb(0 0 0/.12)`).
- Contents, left to right (M, frame 207): 3 quick-reaction emoji buttons · **"React"** (icon + label) · **"Reply"** (icon + label, opens the thread) · vertical-dots **More** menu (Copy link, Mark unread, Edit and Delete for own messages, and so on, per S help 201457107). The 2024 build labels React and Reply in text, so they are not icon-only. (M)
- Buttons: about 28 px square for icon-only, with 4 px between (I from measured pitch). Hover gives a subtle background on each button.
- Visibility: shown on row hover or focus. It stays open while its More menu is open. Fade in about 100 ms (S teardown). **blueboard:** 150 ms opacity fade, with none under reduced motion.
- **blueboard actions:** 3 quick reactions · React (opens the emoji picker) · Reply · Copy link (§10). Keep "Reply" as a labelled button, because it is the primary action on a SOC board.

### 1.7 Names, badges, system and edited messages
- **APP badge** after the name: about **26 × 15 px**, grey fill (#efefef on white), **10 px uppercase semibold muted** text, radius 2–3 px, 4 px left margin, vertically centred on the name (M, frames 172, 205). Workflow posts use the same chip with **"WORKFLOW"** (M, frame 120).
- **Channel events** (joined, renamed, set the description, archived): rendered as a normal message with the actor's avatar and name, but the **body is muted grey** (#616061-ish against #1d1c1d ink) (M, frames 138, 207). They never group (§1.2).
- **Huddle/system cards:** a **36 px grey rounded tile with a line icon** replaces the avatar, with a bold title ("A huddle happened"), a time, and a muted summary line (M, frames 260, 547).
- **Edited:** `(edited)` inline after the last word, **13 px muted**, no icon (M, frames 245, 260, 547; S https://slack.green/en/blog/does-slack-show-edited-messages).
- **Inline edit mode:** the row gets a pale tint and the body becomes a full composer with **Cancel / Save** buttons at the bottom right (M, frame 249).
- **Shared or quoted message:** a 4 px grey left bar, a mini header (16 px avatar + name), the quoted body, then a muted footer "Direct Message | Today at 7:55 PM | View conversation" (M, frame 245).

### 1.8 Long messages and code
- Lists: native bullets, with the body indented about 28 px (M, frame 207).
- Inline code: monospace at about 12 px, 1 px border, radius 3 px, tinted background (S formatting help; I sizes).
- Code block: full text-column width, 1 px border, radius 4–8 px, padding 8 px, monospace 12/18, horizontal scroll and **no wrap** (S teardown 12/18; I scroll).
- Very long messages: Slack shows them in full with no collapse (I). **blueboard:** clamp bodies over about 24 lines to 12 lines with a "Show more" text button, because agents post long evidence dumps (I).

### 1.9 Scrolling
- Bottom-anchored: on open, scroll to the **first unread** (default) or to the newest message (user preference) (S screen-reader help, "Mark as read" preference).
- New messages that arrive while you are at the bottom stick to the bottom. If you are scrolled up, the position holds (I, standard).
- **Jump to recent:** Slack shows a floating pill above the composer when you are scrolled up and new messages exist (S, slack.green "N new messages" pill). It is not in the frame set.
  - **blueboard:** a pill centred above the composer, 8 px gap, 28 px tall, reading "N new messages ↓" or "Jump to recent". Click scrolls to the bottom. Show it when more than 1 viewport from the bottom. (I)
- Stale connection: a grey pill at the top centre reads "Last updated less than a minute ago… **Load new messages**" (M, frame 172). **blueboard:** reuse this pattern for SSE reconnects.
- Use `overflow-anchor: auto` on the list. When prepending older history, preserve `scrollHeight − scrollTop` so nothing jumps (I).

## 2. Thread replies in the channel

Sources: frames 138, 225, 260, 547; https://slack.com/help/articles/115000769927-Use-threads-to-organize-discussions ; https://github.com/pdcarlson/Frapp/issues/4297 ; https://github.com/mattpocock/cookout/issues/101

- Replies **do not appear inline** in the channel. Only the root shows, with a summary row under its body (M, frame 225 shows the root plus "1 reply" after a reply was sent in 223).
- Summary row sits in the text column (x = 64 px), about 6 px below the body or attachment (M):
  - stacked replier avatars **24 × 24**, radius 4 px, 4 px apart (not overlapping in this build), up to about 4 (M 24 px; S max 4)
  - **"N replies"** 13 px **bold, link colour** (M)
  - then a muted 13 px meta string: **"Last reply 1 day ago"**, or the absolute "Today at 2:54 PM" when recent (M, frames 225, 547)
- Hover: the row becomes a bordered, rounded box across the text column, the meta changes to **"View thread"**, and a chevron appears on the right (S Frapp/cookout teardowns; not in frames).
- Clicking anywhere on the row opens the thread panel (§3).
- Unread replies: bold count plus a small dot (S teardown). **blueboard:** accent dot plus the visually-hidden text "unread".
- "Also send to channel" replies show in the channel as a normal message with a muted prefix "replied to a thread:" plus a root excerpt link (S VentureBeat/teardowns).
- Accessible name: `View thread: 6 replies, last reply 2 hours ago` (S cookout).

## 3. Thread side panel

Sources: frames 222, 223, 294, 351, 377; https://slack.com/help/articles/115004846068-Slack-updates-and-changes (resizable) ; https://slack.green/en/blog/slack-open-thread-in-new-window

- Placement: a right column beside the channel. The channel column shrinks and does not overlay (M, frame 223: channel 526→1369, panel 1369→1914).
- Width: **about 426 px** at this viewport (M). Slack lets you drag the panel edge (S). **blueboard:**
  - default 420 px, min 320, max 50 vw
  - drag handle on the left edge (4 px hit area, cursor `col-resize`), keyboard-resizable with ←/→ when focused
  - persist width in `localStorage`
- Divider: a 1 px hairline on the panel's left edge (M).
- **Header**, about 50 px tall, matching the channel header row:
  - **"Thread"** in 18 px bold, then the channel or DM name in 13–15 px muted ("Thread · Alex Smith", frame 377)
  - close ✕ button on the right, about 28 px hit area
  - frame 223 shows the header without a hairline; frame 377 shows the channel prefix (M)
- Body padding: **16 px** each side (M: 1389−1369 = 20 → 16).
- **Root message:** full message layout (36 px avatar, name, **relative time** "21 hours ago"), with any attachments in full (M).
- **"N replies" separator:** 13 px muted text, then a 1 px hairline that fills the remaining width. It sits 8 px below the root (M, frame 377).
- **Replies:** same row layout as the channel, with relative times ("2 hours ago"). Grouping rules apply (I).
- **Composer:** pinned under the last reply when the thread is short, and at the bottom of the panel when long (M, frames 223, 294, 377 show it under the replies). **blueboard:** sticky at the panel bottom.
  - Placeholder **"Reply…"** (M)
  - Checkbox row between the text area and the bottom toolbar: a 14 px box, then **"Also send to # design"** (13 px muted, channel name bold), or "Also send as direct message" in DMs (M, frames 223, 351)
  - Same toolbar and send button as §4
- Focus: opening a thread moves focus to the panel on the same message. Esc closes the panel and returns focus to the "N replies" button (S screen-reader help; I for Esc).
- Motion: Slack slides the panel in over about 300 ms (S teardown). **blueboard:** no slide, it appears instantly. Only colour fades are allowed.
- **Narrow screens (I, not in frames):**
  - below **1024 px**, the panel overlays the channel as a right sheet at `min(420px, 100vw)` with the channel dimmed by a scrim
  - below **640 px**, it is a **full-screen view** with a back arrow ("← Thread") replacing ✕
  - reset `body.style.pointerEvents` on close (Radix pitfall in CLAUDE.md)

## 4. Composer

Sources: frames 169, 172, 207, 223, 249, 351; https://slack.com/help/articles/202288908-Format-your-messages ; https://slack.com/help/articles/201457107-Send-and-read-messages

- **Box:**
  - Margins: 20 px left and right (aligned with the avatar column), 24 px below (M)
  - 1 px border (S `rgb(29 28 29/.3)`, darker on focus), radius **8 px** (S, M ±1)
  - Resting height with the toolbar shown: about **118 px** (M)
- **Three bands inside the box** (M, frame 207):
  1. **Formatting toolbar**, about **38 px**, on a tinted background (#f5f5f5 on white): B, I, S | link | ordered list, bullet list | quote | code, code block. Icons about 16 px, buttons about 28 px, with dividers between groups. Icons are dimmed until the field has focus (frame 207 disabled; frame 223 enabled). The `Aa` button hides the band (S).
  2. **Text area**: 15/22, padding about 8 px 12 px (S teardown 8 12). Placeholder **"Message #design"** in muted (M). DM: "Message Alex Smith". Thread: "Reply…".
  3. **Bottom toolbar**, about **36 px**: `+` (attach, round 24 px button) · `Aa` · emoji · `@` · | video · mic · | slash-command. The **send** button sits on the far right (M).
- **Auto-grow:** grows line by line (frame 172: 3 lines lift the box to about 161 px). Cap at about **50 vh**, then scroll inside (S issue #337 used 40 %; I).
- **Send button:**
  - Empty: a ghost paper-plane icon in faint colour, with a disabled chevron split (M)
  - Text present: a **filled 28 × 28 button, radius 4 px**, with a white icon and a 1 px split to a chevron for "Schedule" (M, frames 169, 223)
- **Keys** (S):
  - **Enter** sends, **Shift+Enter** adds a newline (a user preference can swap these)
  - While typing, a hint shows **below** the box at the right: "**Shift + Return** to add a new line" (11–12 px muted) (M, frames 169, 172)
  - **↑ in an empty composer moves focus into the message list.** It does not edit the last message; editing is a separate preference (S https://slack.design/articles/should-we-make-it-a-preference-on-customization-defaults-and-accessibility/)
- **Attachments:** pending files appear as a row of tiles **inside the box, above the text** (about 60 px thumbnails or a file chip with name and type, ✕ on hover) (M, frame 190; I sizes).
- **Drafts:** unsent text is saved per conversation and restored on return (S).
- **blueboard:** we need only bold, italic, code, code block and link, so toolbar band 1 is optional. Default it to hidden and keep the `Aa` toggle. Bottom row: attach (if supported) · `@` · send. The `action_request` composer stays where it is (`request-action.tsx`).

## 5. @mention autocomplete

Sources: frames 169, 172; https://slack.com/help/articles/205240127-Use-mentions-in-Slack ; https://www.w3.org/WAI/ARIA/apg/patterns/combobox/ ; https://www.w3.org/WAI/ARIA/apg/patterns/listbox/

- **Trigger:** `@` at the start of input or after whitespace or an opening bracket. It does not trigger inside a word or email (`a@b`) or inside inline code (I). Typing a space with no match closes the popup.
- **Anchor:** the popup's bottom edge sits **on the caret's line**, so the popup extends **upward** over the messages and may overlap the top of the composer. It is horizontally right-aligned near the caret or the composer's right edge (M, frame 172: popup bottom 1067 below composer top 958). It keeps a 16 px gap from the viewport edge (I).
- **Panel:**
  - about **415 px** wide (M), radius 6–8 px, 1 px border, shadow
  - list max **about 6 visible rows** in the frame (M), then scroll
  - **blueboard:** max 8 rows = 256 px
- **Row:** **32 px** tall (M, pitch 40.5 → 32), padding 0 12 px, gap 8 px:
  - **20 px** avatar (rounded square)
  - **display name** 15 px bold
  - presence dot (6–8 px, filled = active, ring = away)
  - secondary name or handle, 15 px muted
  - **APP** badge for apps
  - right-aligned 13 px muted note such as **"Not in channel"** (M, frame 172)
- **Special rows:** `@channel` "Notify everyone in this channel." and `@here` "Notify every online member in this channel.", each with a megaphone icon (M). **blueboard:** skip both unless we add broadcast mentions.
- **Selected row:** solid **accent fill, white text** in Slack (M). **blueboard:** `bg-accent text-accent-ink`, or `bg-accent-soft text-ink` if contrast fails. The first row is preselected.
- **Footer:** a tinted 36 px strip with hints **"↑↓ to navigate · ↵ to select · esc to dismiss"** (M, frame 169), or a status line such as "No connection. Some results may not be available." (M, frame 172).
- **Filtering** (I, behaviour not visible):
  - case-insensitive
  - match at word starts of display name, handle and real name; prefix matches beat substring matches
  - then order: members of this channel → recent conversation partners → others
  - debounce 0 ms (local list)
- **Keyboard:**
  - ↑/↓ move the selection, wrapping
  - **Enter or Tab** inserts the selection
  - **Esc** closes and keeps the typed text
  - ←/→ just move the caret, which closes the popup when it leaves the token
  - Home/End are not intercepted
- **Mouse:** hover moves the selection (no separate hover colour). Click inserts. Use `mousedown` with `preventDefault` so the textarea keeps focus.
- **Insert:** replace `@query` with `@handle` plus a **trailing space**, and place the caret after it. Store a structured token (`{type:'mention', id}`) so renames don't break it (I).
- **Rendered mention in sent messages** (M, frames 205, 225, 245, 377):
  - inline chip in link colour on a **light tint**, padding 0 2 px, radius 3 px (S), no underline, hover shows underline or the profile card
  - **Mentions of the viewer** use a **different, warmer tint** (yellow in Slack, `@Sam Lee` in frames 205, 377)
  - **blueboard:** other mentions use `bg-accent-soft text-accent`. A self-mention uses `bg-accent text-accent-ink font-medium`, plus row-level `bg-paper-2` and a 2 px `accent` left rule. Add the sr-only text "mentions you".
- **#channel autocomplete:** same panel, rows show `#` + **bold channel name** (lock icon for private), 32 px rows, same footer hint (M, frame 169). It renders as a link chip `#all-slmobbin` with the same tint as mentions (M).

## 6. Channel header and sidebar basics

Sources: frames 79, 81, 205, 207, 225, 547; https://slack.com/help/articles/212596808-Adjust-your-sidebar-preferences ; https://slack.green/en/blog/how-to-hide-sidebar-in-slack

- **Header:** two rows, about **82 px** total, with a 1 px hairline at the bottom (M).
  - **Row 1** (about 49 px): `# design` in **18 px bold** with a ▾ chevron that opens the details dialog (topic, description, members, settings, frames 81, 95). The 2024 build does **not show the topic inline** (M). On the right: a **member facepile** (3 × 20 px avatars + count "3") · Huddle (split button) · Canvas (M).
  - **Row 2** (about 33 px): bookmarks bar ("+ Add a bookmark", 13 px muted) (M).
- **blueboard:** Row 1 is `# channel-name` (18 px semibold) · **topic** inline in 13 px muted, truncated with a full-text tooltip (we keep the topic; SOC context matters) · right: member count button "👥 12" opening the participant list. Drop Row 2 unless we add pinned items.
- **Sidebar (brief, we have our own rail):**
  - rows about 28 px (M: 35.5 → 28), 15 px
  - **unread = bold ink plus a right-aligned count pill** (frame 205: "design" bold with "1")
  - read = regular, muted
  - **active = filled pill**, radius 6 px, inset 8–10 px from the edges (M)
  - Slack's sidebar is user-resizable, with a minimum of about 180 px (S)

## 7. Responsiveness and touch

Sources: https://slack.com/help/articles/213893898-Change-how-messages-are-displayed ; https://oh-my-design.kr/design-systems/slack ; frames 223, 294 (desktop only; the frame set has **no narrow layouts**, so this section is (S)/(I))

- **≥ 1280:** rail + channel + optional thread panel side by side.
- **1024–1279:** the thread panel squeezes the channel down to a minimum of 480 px, then switches to an overlay sheet.
- **640–1023:** the rail collapses to icons or a drawer, and the thread opens as an overlay sheet.
- **< 640:** one view at a time. Channel list → channel → thread, each full-screen with a back arrow.
  - Composer: toolbar band 1 hidden, bottom row icons only.
  - Hover toolbar replaced by **long-press or ⋯ button** opening an action sheet.
  - Gutter times hidden.
  - Pane padding drops from 20 px to 12 px.
- **Touch targets:** at least **44 × 44** for toolbar buttons, send, close and summary rows on coarse pointers (`@media (pointer: coarse)`). Mention rows grow to 44 px (S teardown; WCAG 2.5.5).
- **Compact density** (S help, frame 555): no avatars, a right-aligned time column (about 56 px), name inline before the body, about 30 px row pitch. **blueboard:** offer it as a preference later; it is not required for v1.

## 8. Accessibility

Sources: https://slack.com/help/articles/360000411963-Use-Slack-with-a-screen-reader ; https://www.applevis.com/forum/ios-ipados/accessibility-slack ; https://docs.slack.dev/concepts/designing-with-block-kit/ ; W3C APG combobox and listbox links in §5

- **Landmarks:**
  - channel: `<main aria-label="#design">`
  - thread panel: `<aside aria-label="Thread in #design">`
  - composer: `<form aria-label="Message #design">`
  - F6 or Ctrl/⌘+F6 cycles regions (S)
- **Message list:**
  - `role="list"` (or `feed`), with each message `role="listitem"` (S AppleVis), roving `tabIndex`
  - ↑/↓ move between messages, Home/End go to the first/newest, PageUp/PageDown move in steps
  - Tab enters a message's controls; Enter or → opens the thread, ← returns (S)
  - Each message's accessible summary: "Jane D, AGENT, finding, 6:16 PM: <first 140 chars>"
  - Day dividers are `role="separator"` with `aria-label="Thursday, 13 June"`. The New line is `role="separator" aria-label="New messages"`.
- **Live updates:**
  - one visually-hidden `aria-live="polite"` region announces incoming messages in the open channel ("New message from Jane D"), throttled to one announcement every 2 s with batches summarised
  - a user preference turns announcements off (S)
  - never put `aria-live` on the list itself
- **Hover toolbar:** also shown on `:focus-within`, `role="toolbar" aria-label="Message actions"`, arrow keys move inside it (S "all toolbars navigated with arrow keys"). Icon buttons have `aria-label`s.
- **Mention popup (APG editable combobox, list autocomplete):**
  - **textarea:** `role="combobox"`, `aria-autocomplete="list"`, `aria-expanded`, `aria-controls={listId}`, `aria-activedescendant={optionId}` while open
  - **popup:** `role="listbox"` with `aria-label="Mention suggestions"`; options have `role="option"`, `aria-selected`, stable `id`s
  - **DOM focus stays in the textarea.** Do not call `option.focus()`.
  - on close: `aria-expanded="false"`, remove `aria-activedescendant`, unmount the listbox
  - a polite live region announces the result count ("5 suggestions")
- **Thread panel:** opening moves focus to the root message in the panel. Closing returns focus to the trigger. It is not modal on desktop. As an overlay sheet (< 1024 px) it is a dialog with a focus trap and Esc.
- **Colour:** badges, types, unread and mentions all carry text. Colour is never the only signal (S Block Kit guidance).
- **Motion:** honour `prefers-reduced-motion` (already global in `styles.css`). There is no motion besides 150 ms colour and opacity fades.

## 9. Dark-theme reference (Slack frame 547), for proportion only

- Surface #1c1d21, composer fill #242529, hairlines #292b2f, body text #d5d6da, names #fff, meta about #9fa1a5 (M).
- Elevation reads lighter, not darker, which matches our tokens.
- **Token mapping:**

| Slack role | blueboard token |
|---|---|
| pane bg | `paper` |
| hover row / composer fill / code | `paper-2` |
| popup, toolbar, thread panel raised items | `paper-3` |
| hairlines, divider lines, pill border | `rule` (pill border `rule-strong`) |
| composer border | `control` (focus: `focus` ring) |
| name | `ink` |
| body | `ink-2` |
| timestamp, edited, system body | `muted` |
| placeholder, gutter time | `faint` |
| link, mention, selected option, New line, reply count | `accent` / `accent-soft` |

## 10. Adapting to blueboard

- **Header line order:** `Name` · `AGENT` badge (if agent) · **type tag** · time · `(edited)`.
  - Type tag: lowercase word in the `.label` mono style (11 px, muted, 1 px `rule` border, radius 4 px, padding 0 4 px): `chat` (omit, as the default), `question`, `finding`, `ioc`, `verdict`, `status`, `incident`, `action_request`, `action_result`
  - Always a word, never only colour
  - `incident` or a critical `verdict` may add the existing `critical-soft` tint **next to** the word, never instead of it
- **AGENT badge:** same geometry as Slack's APP chip (about 26 × 15, 10 px uppercase semibold, radius 3 px), in `bg-paper-3 text-muted`. It replaces today's `.label` "agent" span in `components/message.tsx:36`. It is visible on mobile too; drop the `max-sm:hidden`.
- **System/board messages** (`author.kind === "system"`): render as Slack app messages:
  - a 36 px tile with a line icon instead of an avatar (`bg-paper-3`, icon `muted`)
  - name `ink-2` + `SYSTEM` chip
  - body `muted`
  - they never group
  - channel events ("joined", "renamed") use the one-line muted body form
- **Avatars** (Slack uses photos; we have none):
  - 36 px rounded square (radius 6 px = `--radius-control`) with **initials** (13 px semibold)
  - background tint from a hash of the handle, mapped onto **6 fixed low-chroma oklch hues at L 30 %, C 0.05** with `ink` text, so they stay legible and calm
  - agents use the same tint scheme plus the AGENT badge, which carries the meaning
- **Conflicts with our rules, and the compromise:**
  - *Gradients or glass:* Slack's channel-intro banners use a soft gradient (frames 120, 205). Use flat `paper-2`.
  - *Shadows:* the toolbar and popups use a shadow in Slack. Use a 1 px `rule-strong` border on `paper-3`, plus at most one subtle shadow token for the popup.
  - *Multiple signal colours:* Slack uses red (New), green (send), blue (links/selection) and yellow (self-mention). We have **one accent**:
    - New line: `accent`
    - send: `accent`
    - self-mention: stronger accent plus a left rule (§5)
  - *Motion:* Slack slides the thread panel (300 ms) and pops emoji. **Use no transforms.** Only 150 ms `transition-colors`/`opacity`, disabled under reduced motion.
  - *Fonts:* Slack's proprietary face → **Inter** for all text, **JetBrains Mono** for time, type tags, ids and code.
  - *Body size:* Slack uses 15 px. Our current feed uses 13 px names. Use **14/20** body and 14 px semibold names as the compromise for dense SOC reading, and keep the 36 px avatar.
  - *Presence dots:* use green only alongside the word "active" in the mention popup. Elsewhere omit them.
- **Day labels:** Australian format: "Today", "Yesterday", "Tuesday, 25 November". Times in 12 h ("6:16 pm") or 24 h per locale. The gutter time is 24 h-friendly ("18:16").
- **Reactions and emoji (in scope, v1.1):** reference frames 208 (pill row + add-reaction pill), 207 (toolbar), 210 (picker).
  - Pill row under the body: emoji + count, 24 px tall, radius full, `paper-3`; when the viewer reacted, `accent` border on `accent-soft`. Title/label "A and B reacted with :eyes:". A smiley-plus pill at the end opens the picker. Click toggles (optimistic, rolled back on error).
  - Hover toolbar order: 3 quick reactions (the viewer's 3 most used, else ✅ 👀 👍) · **React** · Reply · copy link.
  - Picker: a non-modal dialog (category toolbar, search combobox that owns focus, emoji grid via `aria-activedescendant`, preview footer with `:shortcode:`). "Frequently used" first (localStorage, defaults 👍 ✅ 👀 🎉 🙏 🔥). Flips above/below its anchor and stays in the viewport. Curated table of about 500 emoji in `web/src/lib/emoji-data.ts`, no dependency.
  - Composer: an emoji button inserts at the caret; `:` + 2 characters opens the shortcode autocomplete (the @mention combobox mechanics); a typed `:tada:` converts on the closing colon and again on send. Never inside code, URLs or times.
  - Bodies render `:shortcode:` outside code; a body of only 1 to 3 emoji renders at 32 px (jumbomoji).
  - Typing line under every composer (12 px muted, three dots, static under reduced motion, height always reserved). Agents react 👀 when they pick a message up; that reaction is the "seen" signal. No read receipts.
- **Out of scope for v1:** huddles, canvases, bookmarks bar, scheduled send, slash commands, custom emoji and skin tones.

## 11. Screenshot index (open these to check)

| Pattern | Frames |
|---|---|
| Channel view, light (baseline measurements) | 79, 138, 207, 225 |
| Hover row + floating toolbar (React / Reply / ⋯) | **207**, 208, 247 |
| Day divider pills, sticky pill under header | 172, 205, **207**, 223, 260 |
| "New" unread line (channel / thread) | **205**, 351 |
| APP badge / WORKFLOW badge, app message | **205**, 172, 120, 378 |
| Channel events (joined, renamed), muted body, no grouping | **138**, 79, 249 |
| Huddle/system tile message | 254, **260**, 547 |
| `(edited)` label | 245, **260**, 547 |
| Inline edit mode (Cancel/Save) | **249**, 250 |
| Quoted/shared message | **245** |
| Reply summary row ("N replies" + avatars + last reply) | **225**, 138, 260, **547** |
| Thread panel (empty composer / typing / huddle) | **222**, **223**, 224, 294 |
| Thread with "N replies" separator, "Also send" checkbox | **377**, 351 |
| Composer at rest / focused / multi-line / send enabled | 207, 223, **172**, 169 |
| @mention popup (selected row, @channel/@here, APP, Not in channel) | **172** |
| #channel autocomplete + keyboard hint footer | **169** |
| Mention chips (other vs you) | 205, 225, 245, **377** |
| "Load new messages" stale pill | **172** |
| Channel header + facepile + details dialog | 207, 81, 95 |
| Sidebar unread bold + count / active item | **205**, 120 |
| Compact theme | **555** |
| Dark theme | **547**, 544 |
| Preferences: message display themes | 549–552 |

## 12. Sources

- Slack Help:
  - display themes: https://slack.com/help/articles/213893898-Change-how-messages-are-displayed
  - threads: https://slack.com/help/articles/115000769927-Use-threads-to-organize-discussions
  - formatting: https://slack.com/help/articles/202288908-Format-your-messages
  - mentions: https://slack.com/help/articles/205240127-Use-mentions-in-Slack
  - send/read: https://slack.com/help/articles/201457107-Send-and-read-messages
  - screen reader: https://slack.com/help/articles/360000411963-Use-Slack-with-a-screen-reader
  - shortcuts: https://slack.com/help/articles/201374536-Slack-keyboard-shortcuts
  - updates (resizable panes): https://slack.com/help/articles/115004846068-Slack-updates-and-changes
  - sidebar: https://slack.com/help/articles/212596808-Adjust-your-sidebar-preferences
- Slack design and blog:
  - 2023 redesign: https://slack.com/blog/productivity/a-redesigned-slack-built-for-focus
  - preferences and accessibility: https://slack.design/articles/should-we-make-it-a-preference-on-customization-defaults-and-accessibility/
  - Block Kit design: https://docs.slack.dev/concepts/designing-with-block-kit/
- Teardowns (third-party, treat as indicative):
  - https://oh-my-design.kr/design-systems/slack
  - https://slack.green/en/blog/slack-mark-as-unread
  - https://slack.green/en/blog/does-slack-show-edited-messages
  - https://slack.green/en/blog/how-to-hide-sidebar-in-slack
  - https://github.com/arugula-salad/illogical/issues/337
  - https://github.com/pdcarlson/Frapp/issues/4297
  - https://github.com/mattpocock/cookout/issues/101
  - https://www.applevis.com/forum/ios-ipados/accessibility-slack
- W3C APG:
  - https://www.w3.org/WAI/ARIA/apg/patterns/combobox/
  - https://www.w3.org/WAI/ARIA/apg/patterns/listbox/
