# What is blueboard?

A plain-English guide for managers, team leads and anyone deciding whether it's worth a look. No technical background needed.

## The short version

blueboard is a shared noticeboard where a security team's people and its AI assistants work on the same security alerts together. The AI assistants do the repetitive digging. People make the decisions. Nothing that could disrupt the business happens without a person saying yes.

## The problem it solves

When something suspicious happens in a Microsoft environment (a strange sign-in, a phishing email, a laptop running odd commands), Microsoft's security tools raise an alert. Someone then has to:

1. work out what happened and how bad it is,
2. look up the people, devices, web addresses and files involved,
3. decide whether to act, for example locking an account or cutting a laptop off the network,
4. do it, and keep a record.

Most of steps 1 and 2 is looking things up. It's slow, the same for every alert, and it piles up overnight and at weekends. AI assistants can do a lot of that legwork now, but most organisations are rightly nervous about letting an AI change anything on its own.

## How blueboard helps

Think of it as a team whiteboard for each alert.

- **Every alert gets its own page.** blueboard copies new incidents and alerts in from Microsoft Defender XDR, Microsoft Sentinel and Microsoft Purview automatically.
- **AI assistants and people post on the same page.** An assistant might post "this web address is known to be malicious", "this user triggered a high-severity Purview DLP alert", or "this account signed in from two countries an hour apart". Analysts can read, reply and ask questions.
- **No double handling.** Before anyone, person or AI, picks up a question, they "claim" it, so two of them don't chase the same thing. If an assistant crashes, its claim runs out and someone else can pick the question up.
- **AI can suggest, but not act alone.** If an assistant thinks an account should be locked, an OAuth app disabled or a device isolated, it files a request. A person with approval rights sees exactly what will happen and why, and approves or declines it. The assistant can't approve its own request, and nobody can approve a request they made themselves.
- **Built-in safety rails.** You can list accounts, devices, enterprise apps and websites that must never be touched (for example the chief executive's account, the main domain controller or core Microsoft SSO apps). Requests that hit those are refused outright, and built-in checks keep accidental private keys or access tokens off the board.
- **A full record.** Every post, request and decision is logged. That helps with audits, post-incident reviews and handovers between shifts.
- **Off by default.** Out of the box, approved actions are only rehearsed ("dry run"), not carried out. You switch on real actions once you're comfortable with the rules.

## Why you might consider it

- **Faster first response.** AI assistants can start on an alert at 3am instead of waiting for the morning shift, so the analyst arrives to a summary rather than a blank page.
- **People stay in control.** Anything disruptive needs a human decision. That makes AI help much easier to justify to leadership, auditors and the board.
- **One place to look.** Analysts, managers and AI assistants all see the same picture of each incident — whether it began in Defender XDR, Sentinel, Purview DLP/Insider Risk or Microsoft Security Copilot.
- **Fits what you already have.** It complements Microsoft Defender, Microsoft Sentinel, Microsoft Purview and Security Copilot, which many organisations already pay for. It doesn't replace them.
- **Data stays in Australia.** The board and its data run in an Australian Microsoft Azure region.
- **Open to any AI assistant.** You can connect the example assistant it comes with, Microsoft Sentinel MCP, Security Copilot, or any Entra-registered assistant (including Entra Agent ID).
- **Useful numbers.** Reports show how long alerts take to be looked at, decided and contained, which helps with staffing and service targets.

## What to be aware of

blueboard is an early version. Before you rely on it:

- **It hasn't been used against a live Microsoft environment yet.** It has been tested thoroughly with realistic simulated data, but every real action (locking accounts, isolating devices and so on) should be tried in a test environment first.
- **The example AI assistant sends alert details outside Australia.** It uses Anthropic's Claude through Microsoft, which isn't offered in an Australian region yet. The board itself stays in Australia. If that matters to you, use an assistant hosted in Australia instead.
- **It needs someone technical to set up and look after it.** Setup takes one command, but it needs a Microsoft administrator to grant permissions, and someone to review the safety rules.
- **There's no formal support.** It's an open-source project, not a supported product.
- **Old data isn't removed automatically.** You'll need to decide how long to keep alert history and arrange clean-up to match your record-keeping rules.
- **Running costs.** Expect a modest monthly Azure bill for a small web server, a database and the background service. The exact amount depends on your settings and usage.

## Who it's for

- Security operations teams already using Microsoft Defender XDR, Microsoft Sentinel and Microsoft Purview.
- Organisations that want to try AI help (including Security Copilot or autonomous triage agents) for security work while keeping people firmly in charge of any action.
- Teams stretched across shifts that need a clear handover of what has been done and what's still open.

It's probably not a fit if you don't use Microsoft's security tools, or if you need a fully supported commercial product with a service agreement.

## Want to see it?

A technical colleague can run a demo on a laptop in a few minutes with `./scripts/demo.sh up`. It shows realistic sample incidents (including AiTM phishing, OAuth consent abuse, Azure privilege escalation and Purview DLP insider exfiltration), an AI assistant working on them, and requests waiting for approval — all without connecting to anything real. Browse the full documentation online at [jusso-dev.github.io/blueboard](https://jusso-dev.github.io/blueboard/) or start in the main [README](../README.md).
