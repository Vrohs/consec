# consec — Complete UX Blueprint for Showcase Website

**For:** UI/UX Designer
**From:** Advait (project developer)
**Goal:** A single-page showcase website where Advait plugs in his CLI tool's real output and has a complete, presentable project showcase — for academic evaluation, portfolio, and GitHub visitors.

**IMPORTANT:** This is a COMPLETE blueprint. Design every section as part of ONE connected page — not isolated pieces. The page tells a story from top to bottom. Every section flows into the next.

---

## Part 1: The Story This Page Tells

The visitor (professor, recruiter, developer) lands on the page and experiences this narrative in order:

```
HOOK          "This looks impressive, what is it?"
  │
  ▼
PROBLEM       "Oh, container security is a real mess..."
  │
  ▼
SOLUTION      "...and this tool fixes it. Smart."
  │
  ▼
FEATURES      "It does a lot — 7 commands, interesting."
  │
  ▼
HOW IT WORKS  "The AI pipeline is technically serious."
  │
  ▼
LIVE PROOF    "I can see it actually working."
  │
  ▼
CREDIBILITY   "10 security rules, strong numbers, real tech stack."
  │
  ▼
TRY IT        "Easy to install. Let me check the GitHub."
  │
  ▼
CREDITS       "Built by Advait. MIT license."
```

**Every section must visually lead into the next.** No hard cuts. The background gradient, spacing, and visual cues should make scrolling feel like one continuous experience.

---

## Part 2: Full Page Map (Desktop Wireframe)

This is the entire page at a glance. Relative heights show visual weight.

```
┌──────────────────────────────────────────────────────────────────┐
│ ┌─[logo]──────────────────[Features] [How] [Rules] [GitHub ➜]─┐ │ ← Sticky Nav (appears after scrolling past hero)
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│ ══════════════════════════════════════════════════════════════════│
│                                                                  │
│                         > consec_                                │ ← Hero
│                                                                  │
│          AI-Powered Container Security                           │   100vh
│          Private. Local. Zero-Cost.                              │
│                                                                  │
│       [ View on GitHub ]    [ See How It Works ↓ ]               │
│                                                                  │
│ ─ ─ ─ ─ ─ ─ ─ ─ gradient fade ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│                                                                  │
│    THE PROBLEM                                                   │ ← Problem/Solution
│ ┌───────────────────────┐   ┌───────────────────────┐           │
│ │                       │   │                       │           │   ~80vh
│ │   Raw Trivy JSON      │   │  consec formatted     │           │
│ │   (blurred, chaotic)  │   │  (clean, glowing)     │           │
│ │                       │   │                       │           │
│ └───────────────────────┘   └───────────────────────┘           │
│    Without consec              With consec                       │
│                                                                  │
│ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│                                                                  │
│              WHAT CONSEC CAN DO                                  │ ← Features
│                                                                  │
│    ┌─────────┐  ┌─────────┐  ┌─────────┐                       │   ~90vh
│    │  scan   │  │  parse  │  │ ingest  │                       │
│    └─────────┘  └─────────┘  └─────────┘                       │
│    ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐         │
│    │  query  │  │ review  │  │  check  │  │ export  │         │
│    └─────────┘  └─────────┘  └─────────┘  └─────────┘         │
│                                                                  │
│ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│                                                                  │
│              HOW THE AI WORKS                                    │ ← Architecture
│                                                                  │
│    [SCAN]───►[EMBED]───►[STORE]───►[QUERY]───►[GENERATE]       │   ~80vh
│    Trivy     Sentence    ChromaDB   Semantic    Ollama LLM      │
│              Transform              Search                       │
│                                                                  │
│ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│                                                                  │
│              SEE IT IN ACTION                                    │ ← Live Demo
│                                                                  │
│    ┌─── Terminal Window ─────────────────────────────────┐      │   ~70vh
│    │ $ consec check Dockerfile                           │      │
│    │ ┌────────────────────────────────────────────┐      │      │
│    │ │ Rule    │ Severity │ Issue                 │      │      │
│    │ │ CSC-001 │ HIGH     │ Unpinned base image   │      │      │
│    │ │ CSC-002 │ HIGH     │ No USER directive     │      │      │
│    │ └────────────────────────────────────────────┘      │      │
│    └─────────────────────────────────────────────────────┘      │
│                                                                  │
│ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│                                                                  │
│              10 BUILT-IN SECURITY RULES                          │ ← Rules
│                                                                  │
│    ┌──────────────────────────────────────────────────┐         │   ~80vh
│    │ CSC-001  🔴 HIGH     Unpinned base images       │ ← click │
│    │ CSC-002  🔴 HIGH     Running as root            │         │
│    │ CSC-003  🟡 MEDIUM   Missing HEALTHCHECK        │         │
│    │ ...                                              │         │
│    └──────────────────────────────────────────────────┘         │
│                                                                  │
│ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│                                                                  │
│    ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐     │ ← Metrics
│    │1,500+│ │ 100+ │ │  10  │ │  7   │ │  4   │ │  $0  │     │   ~40vh
│    │lines │ │tests │ │rules │ │cmds  │ │prompts│ │ cost │     │
│    └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘     │
│                                                                  │
│ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│                                                                  │
│    BUILT WITH                                                    │ ← Tech Stack
│    [Python] [Typer] [Rich] [Pydantic] [ChromaDB] [LangChain]   │   ~30vh
│    [Ollama] [Sentence-Transformers] [Docker] [Trivy] [pytest]   │
│                                                                  │
│ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│                                                                  │
│              GET STARTED                                         │ ← Install
│    ┌─── Terminal ────────────────────────────────────┐          │   ~50vh
│    │ pip install consec                              │          │
│    │ consec scan nginx:latest                        │          │
│    │ consec check Dockerfile                         │          │
│    └─────────────────────────────────────────────────┘          │
│                                                                  │
│         [ View on GitHub ➜ ]                                     │
│                                                                  │
│ ════════════════════════════════════════════════════════════════ │
│    > consec_                                                     │ ← Footer
│    Built by Advait · Chitkara University · MIT License           │   ~20vh
│    [GitHub]                                                      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Part 3: Design Tokens (Use These Everywhere)

### Colors

| Token Name | Hex | Where to Use |
|------------|-----|-------------|
| `bg-base` | `#0A0A0F` | Page background (top) |
| `bg-deep` | `#12121A` | Page background (bottom sections) |
| `surface` | `#1A1A2E` | Cards, panels, elevated containers |
| `surface-hover` | `#22223A` | Card hover states |
| `border-subtle` | `rgba(255,255,255,0.06)` | Card borders, dividers |
| `border-glow` | `rgba(0,212,170,0.3)` | Active/focused element borders |
| `accent` | `#00D4AA` | Primary buttons, highlights, "secure" state, logo cursor |
| `accent-glow` | `rgba(0,212,170,0.15)` | Background glow behind accent elements |
| `severity-critical` | `#FF4757` | CRITICAL badges |
| `severity-high` | `#FF6B35` | HIGH badges |
| `severity-medium` | `#FFC048` | MEDIUM badges |
| `severity-low` | `#4A90D9` | LOW badges |
| `text-primary` | `#E8E8F0` | Headings, primary body text |
| `text-secondary` | `#8888A0` | Descriptions, labels, captions |
| `text-muted` | `#555570` | Disabled states, background text |

### Typography

| Role | Font | Weight | Size (Desktop) | Size (Mobile) |
|------|------|--------|-----------------|---------------|
| Nav links | Inter | 500 | 14px | 14px |
| Section overline | Inter | 600, uppercase, letter-spacing 3px | 12px | 11px |
| Section heading | Inter | 700 | 48px | 32px |
| Section subtext | Inter | 400 | 18px | 16px |
| Card title | Inter | 600 | 20px | 18px |
| Card body | Inter | 400 | 14px | 14px |
| Body text | Inter | 400 | 16px | 15px |
| Code / terminal | JetBrains Mono | 400 | 14px | 12px |
| Stat number | Inter | 800 | 64px | 40px |
| Stat label | Inter | 500 | 14px | 12px |
| Hero title | Inter | 800 | 72px | 40px |
| Hero subtitle | Inter | 400 | 20px | 16px |
| Button text | Inter | 600 | 15px | 14px |

### Spacing

| Token | Value | Usage |
|-------|-------|-------|
| `section-padding-y` | 120px (desktop) / 80px (mobile) | Vertical padding inside each section |
| `section-gap` | 0px | Sections are flush — background gradients create separation |
| `content-max-width` | 1200px | Max width of content area, centered |
| `card-padding` | 24px | Internal padding of all cards |
| `card-gap` | 24px | Gap between cards in grid |
| `card-radius` | 16px | Border radius on cards |
| `button-radius` | 12px | Border radius on buttons |
| `element-gap` | 16px | Default gap between stacked elements |

---

## Part 4: Component Library

Design these components ONCE, then reuse them across sections.

### Component 1: Section Header

Used at the top of every section (except Hero and Footer).

```
┌──────────────────────────────────────────────────┐
│                                                    │
│              OVERLINE TEXT (12px, accent color,     │
│                uppercase, letter-spaced)            │
│                                                    │
│         Main Heading (48px, bold, white)            │
│                                                    │
│    Supporting text that explains the section        │
│        (18px, text-secondary, max 60ch)            │
│                                                    │
└──────────────────────────────────────────────────┘
```

Always centered. Overline is always `accent` color. Max-width on subtext: 600px.

---

### Component 2: Terminal Block

A realistic terminal window mockup. Used in: Problem/Solution, Live Demo, Installation.

```
┌─────────────────────────────────────────────────────────────┐
│ ● ● ●                        consec                         │ ← Window chrome bar
│─────────────────────────────────────────────────────────────│    (dark surface color,
│                                                               │     3 dots: #FF5F57
│  $ consec check Dockerfile                                    │     #FEBC2E #28C840)
│                                                               │
│  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓  │
│  ┃          Dockerfile Security Findings (3)              ┃  │ ← Content area:
│  ┣━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫  │    bg-base color,
│  ┃ Rule    ┃ Severity ┃ Issue                             ┃  │    JetBrains Mono,
│  ┡━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩  │    14px
│  │ CSC-001 │ HIGH     │ Unpinned base: node:latest        │  │
│  │ CSC-002 │ HIGH     │ No USER directive (runs as root)  │  │ ← Severity text is
│  │ CSC-006 │ HIGH     │ Secret in ENV: DB_PASSWORD         │  │    colored with
│  └─────────┴──────────┴───────────────────────────────────┘  │    severity-high color
│                                                               │
│  ✗ 3 findings (3 HIGH). Fix before deploying.                │
│                                                               │
└─────────────────────────────────────────────────────────────┘

Border: 1px border-subtle
Corner radius: card-radius (16px)
Shadow: 0 20px 60px rgba(0,0,0,0.5)
```

---

### Component 3: Feature Card

Used in the Features grid. 7 cards total.

```
┌───────────────────────────────────┐
│                                     │
│   [Icon]  (24x24, accent color)     │   ← Top-left icon
│                                     │
│   Card Title (20px, bold, white)    │
│                                     │
│   One-line description of what      │
│   this command does. (14px,         │
│   text-secondary)                   │
│                                     │
│   ┌─────────────────────────────┐  │
│   │ $ consec scan nginx:latest  │  │   ← Mini terminal snippet
│   └─────────────────────────────┘  │      (bg-base, monospace,
│                                     │       12px, no window chrome)
│   Requires LLM? No ✓               │   ← Small badge: green "No"
│                                     │      or accent "Yes"
└───────────────────────────────────┘

Background: surface
Border: 1px border-subtle
On hover: border becomes border-glow, translateY(-4px), shadow increases
Card size: equal height in grid, min-height ~220px
```

---

### Component 4: Severity Badge

Colored pill used in Rules section and terminal output.

```
┌───────────┐
│  ● HIGH   │   ← Dot + text, colored background at 15% opacity
└───────────┘     Text color matches severity color
                  Padding: 4px 12px, border-radius: 99px
                  Font: 12px, weight 600, uppercase
```

Variants: CRITICAL (severity-critical), HIGH (severity-high), MEDIUM (severity-medium), LOW (severity-low)

---

### Component 5: Rule Row (Expandable)

Used in the Security Rules section. 10 rows.

```
COLLAPSED:
┌──────────────────────────────────────────────────────────────┐
│  CSC-001    [● HIGH]    Unpinned or :latest base images   ▼  │
└──────────────────────────────────────────────────────────────┘

EXPANDED (on click):
┌──────────────────────────────────────────────────────────────┐
│  CSC-001    [● HIGH]    Unpinned or :latest base images   ▲  │
│──────────────────────────────────────────────────────────────│
│                                                                │
│  ✗ Bad                              ✓ Fixed                    │
│  ┌──────────────────────┐          ┌──────────────────────┐  │
│  │ FROM node:latest     │          │ FROM node:20.11.1    │  │
│  └──────────────────────┘          └──────────────────────┘  │
│   (red-tinted background)           (green-tinted background) │
│                                                                │
│  Why: Unpinned images can change unexpectedly, introducing     │
│  vulnerabilities or breaking builds.                           │
│                                                                │
└──────────────────────────────────────────────────────────────┘

Background: surface
Border: 1px border-subtle
Expanded area: slightly darker than surface
Transition: smooth height animation (300ms ease)
```

---

### Component 6: Stat Counter

Used in Metrics section. 6 counters in a row.

```
┌───────────────┐
│               │
│    1,500+     │  ← stat number: 64px, bold, text-primary
│               │
│  lines of     │  ← label line 1: 14px, text-secondary
│  source code  │  ← label line 2
│               │
└───────────────┘

No background — these sit directly on the section background.
Numbers animate (count up from 0) when section scrolls into view.
```

---

### Component 7: Pipeline Node

Used in the Architecture section. 5 nodes connected by lines.

```
     ┌───────────────────┐
     │   [Icon]           │   ← Technology icon (32x32)
     │                    │
     │   SCAN             │   ← Step label (14px, accent, uppercase)
     │   Docker + Trivy   │   ← Description (12px, text-secondary)
     └───────────────────┘
              │
              │ ← Connecting line (1px, accent at 40% opacity)
              │   Animated: a dot of light travels along this line
              ▼
     ┌───────────────────┐
     │   [Icon]           │
     │   EMBED            │
     │   Sentence-BERT    │
     └───────────────────┘

Node: surface background, border-subtle, card-radius
Size: ~160x100px
On desktop: nodes are horizontal, lines go left-to-right
On mobile: nodes stack vertically, lines go top-to-bottom
```

---

### Component 8: CTA Button

Two variants used across the page.

```
PRIMARY:                              GHOST:
┌─────────────────────┐              ┌─────────────────────┐
│  View on GitHub  ➜  │              │  See How It Works ↓ │
└─────────────────────┘              └─────────────────────┘

PRIMARY:                              GHOST:
  bg: accent                           bg: transparent
  text: bg-base (#0A0A0F)            text: text-primary
  border: none                         border: 1px text-muted
  hover: accent + brighten 10%        hover: border becomes accent,
  shadow: 0 4px 20px accent-glow       text becomes accent
  padding: 14px 28px                   padding: 14px 28px
```

---

### Component 9: Sticky Navigation Bar

Appears after scrolling past the Hero section. Stays fixed at top.

```
┌──────────────────────────────────────────────────────────────┐
│  > consec_         Features   How It Works   Rules   GitHub ➜│
└──────────────────────────────────────────────────────────────┘

Background: bg-base at 80% opacity + backdrop-blur(20px)
Border-bottom: 1px border-subtle
Height: 60px
Logo: accent color, JetBrains Mono, 16px
Links: text-secondary, hover → text-primary
Active link (current section): accent color + underline
"GitHub ➜": primary CTA style but small (12px padding)
Appears: fade-in when hero scrolls out of view
Mobile: hamburger icon on right, links in dropdown
```

---

## Part 5: Section-by-Section Specifications

---

### SECTION 1: HERO

**Purpose:** First impression. Communicate what consec is in 3 seconds.

**Viewport:** 100vh (full screen)

**Desktop wireframe:**
```
┌──────────────────────────────────────────────────────────────┐
│                                                                │
│                                                                │
│                                                                │
│                        > consec_                               │  ← Logo/wordmark
│                                                                │     JetBrains Mono, 24px
│                                                                │     accent color
│             AI-Powered Container Security                      │     Blinking cursor animation
│                                                                │
│              Private. Local. Zero-Cost.                         │  ← Tagline: hero title size
│                                                                │     Three words, separated by
│                                                                │     dots (styled as accent-
│     Enhance Trivy vulnerability scans with                     │     colored dots or bullets)
│          local LLM intelligence.                               │
│                                                                │  ← Subtitle: hero subtitle size
│                                                                │     text-secondary color
│        [ View on GitHub ]    [ See How It Works ↓ ]           │
│                                                                │  ← Two buttons: primary + ghost
│                                                                │     Side by side, 16px gap
│                                                                │
│                                                                │
│                          ↓                                     │  ← Subtle scroll indicator
│                                                                │     (bouncing arrow, text-muted)
└──────────────────────────────────────────────────────────────┘
```

**Mobile wireframe:**
```
┌──────────────────────┐
│                        │
│                        │
│      > consec_         │
│                        │
│   AI-Powered           │
│   Container Security   │
│                        │
│   Private. Local.      │
│   Zero-Cost.           │
│                        │
│   Enhance Trivy scans  │
│   with local LLM       │
│   intelligence.        │
│                        │
│   [ View on GitHub  ]  │
│   [ How It Works  ↓ ]  │
│                        │
│          ↓             │
└──────────────────────┘
```

**Exact copy:**
- Logo: `> consec_` (the `>` and `_` are accent-colored, `consec` is text-primary)
- Heading: `AI-Powered Container Security`
- Tagline: `Private. Local. Zero-Cost.` (the dots/periods are accent-colored)
- Subtitle: `Enhance Trivy vulnerability scans with local LLM intelligence.`
- Button 1: `View on GitHub` (primary) — links to https://github.com/Vrohs/consec
- Button 2: `See How It Works ↓` (ghost) — smooth-scrolls to Architecture section

**Background:** Subtle animated dot grid pattern (dots: text-muted at 20% opacity, spaced ~40px apart). Optional: very slow radial gradient pulse centered behind the logo (accent-glow color). No particles, no floating icons — keep it clean.

**Transition to next section:** Background gradient darkens slightly from bg-base to bg-deep as you scroll down. No hard line — seamless.

---

### SECTION 2: PROBLEM → SOLUTION

**Purpose:** Show WHY consec exists. Before/after transformation.

**Section ID:** `#problem` (for nav link if needed)

**Desktop wireframe:**
```
┌──────────────────────────────────────────────────────────────┐
│                                                                │
│                     THE PROBLEM                                │  ← Section header
│                                                                │     (overline only,
│    Container security scanners dump raw data.                  │      no main heading —
│    consec makes it understandable.                             │      the two panels ARE
│                                                                │      the content)
│  ┌────────────────────────┐    ┌────────────────────────────┐│
│  │ WITHOUT CONSEC          │    │ WITH CONSEC                ││
│  │                         │    │                            ││
│  │ {                       │    │ ┏━━━━━━━━━━━━━━━━━━━━━━━┓ ││
│  │   "Results": [          │    │ ┃ Vulnerability Summary  ┃ ││
│  │     {                   │    │ ┣━━━━━━┳━━━━━━┳━━━━━━━━━┫ ││
│  │       "Target": "nginx",│    │ ┃ CVE  ┃ Sev. ┃ Fix     ┃ ││
│  │       "Vulnerabilities":│    │ ┡━━━━━━╇━━━━━━╇━━━━━━━━━┩ ││
│  │       [                 │    │ │ 6119 │ HIGH │ 3.3.2   │ ││
│  │         {               │    │ │ 5535 │ MED  │ 1.1.1t  │ ││
│  │           "VulnID":     │    │ └──────┴──────┴─────────┘ ││
│  │           "CVE-2024-... │    │                            ││
│  │           "Severity":   │    │ AI: "CVE-2024-6119 is a   ││
│  │           "HIGH",       │    │ certificate verification   ││
│  │           "PkgName":    │    │ bypass in OpenSSL. Update  ││
│  │           ...           │    │ to 3.3.2 to fix."          ││
│  │                         │    │                            ││
│  └────────────────────────┘    └────────────────────────────┘│
│                                                                │
│   Raw data. Hundreds of CVEs.     AI-explained. Prioritized.  │
│   No guidance.                     Actionable.                 │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

**Left panel (Problem):**
- Background: surface, but slightly red-tinted (`rgba(255,71,87,0.03)`)
- Border: border-subtle with a faint red tint
- Content: Realistic-looking Trivy JSON output in JetBrains Mono, 12px, text-muted color (deliberately hard to read)
- Caption below: `Raw data. Hundreds of CVEs. No guidance.` (text-secondary, 14px)
- Visual feel: slightly blurred/opacity-reduced to look overwhelming

**Right panel (Solution):**
- Background: surface with a slight green/teal tint (`rgba(0,212,170,0.03)`)
- Border: border-glow
- Content: Clean terminal-style table (use Terminal Block component but simplified) + an AI explanation paragraph below it
- Caption below: `AI-explained. Prioritized. Actionable.` (accent color, 14px)
- Visual feel: crisp, glowing, inviting — a subtle accent-glow shadow behind the panel

**Exact copy:**
- Overline: `THE PROBLEM`
- Subtitle: `Container security scanners dump raw data. consec makes it understandable.`
- Left caption: `Raw data. Hundreds of CVEs. No guidance.`
- Right caption: `AI-explained. Prioritized. Actionable.`
- Left panel content: Raw JSON (use this exact text):
```json
{
  "Results": [{
    "Target": "nginx:1.25.3 (debian 12.2)",
    "Vulnerabilities": [{
      "VulnerabilityID": "CVE-2024-6119",
      "PkgName": "libssl3",
      "InstalledVersion": "3.0.11-1~deb12u2",
      "Severity": "HIGH",
      "Title": "openssl: Possible denial...",
```
- Right panel content: Clean table showing 3 CVEs with severity colors, followed by:
```
AI Explanation:
"CVE-2024-6119 is a certificate verification bypass in
OpenSSL 3.x. An attacker could exploit this during TLS
handshake. Update libssl3 to 3.3.2+ to remediate."
```

**Mobile:** Stack panels vertically — Problem on top, Solution below. Same styling.

**Transition to next:** Subtle gradient shift. No hard line.

---

### SECTION 3: FEATURES (7 Commands)

**Purpose:** Show the breadth of what consec can do.

**Section ID:** `#features`

**Desktop wireframe:**
```
┌──────────────────────────────────────────────────────────────┐
│                                                                │
│                      CAPABILITIES                              │  ← Overline
│                What consec Can Do                              │  ← Heading
│       7 commands for scanning, analyzing, and securing         │  ← Subtext
│                  your containers.                              │
│                                                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │   scan   │  │  parse   │  │  ingest  │  │  query   │     │  ← Row 1: 4 cards
│  │          │  │          │  │          │  │          │     │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘     │
│                                                                │
│     ┌──────────┐  ┌──────────┐  ┌──────────┐                 │
│     │  review  │  │  check   │  │  export  │                 │  ← Row 2: 3 cards, centered
│     │          │  │          │  │          │                 │
│     └──────────┘  └──────────┘  └──────────┘                 │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

**Exact card content (all 7):**

| # | Icon | Title | Description | Terminal Snippet | LLM? |
|---|------|-------|-------------|-----------------|------|
| 1 | Radar | Scan Images | Run Trivy against any Docker image and get a formatted vulnerability summary | `$ consec scan nginx:latest` | No |
| 2 | FileText | Parse Reports | Load and display existing Trivy JSON scan results with color-coded severity | `$ consec parse scan.json` | No |
| 3 | Database | Build Knowledge | Ingest CVE data into a vector database for semantic AI queries | `$ consec ingest scan.json` | No |
| 4 | Brain | Ask AI | Ask security questions in natural language — answered via RAG pipeline | `$ consec query "Explain CVE-2024-6119"` | Yes |
| 5 | Shield | AI Review | Get an AI-powered security review of your Dockerfile correlated with scan data | `$ consec review Dockerfile` | Yes |
| 6 | CheckSquare | Static Analysis | Run 10 built-in security rules against a Dockerfile — no AI needed | `$ consec check Dockerfile` | No |
| 7 | Download | Export Reports | Generate Markdown or JSON security reports for documentation | `$ consec export scan.json report.md` | No |

**Exact copy:**
- Overline: `CAPABILITIES`
- Heading: `What consec Can Do`
- Subtext: `7 commands for scanning, analyzing, and securing your containers.`

**Mobile:** Cards stack into a single column, full width.

**Transition:** Background stays consistent. A thin horizontal line in border-subtle separates this from the next section, OR just extra spacing.

---

### SECTION 4: HOW IT WORKS (Architecture / RAG Pipeline)

**Purpose:** Show technical depth. This is the "wow, this is real engineering" section.

**Section ID:** `#how-it-works`

**Desktop wireframe:**
```
┌──────────────────────────────────────────────────────────────┐
│                                                                │
│                      ARCHITECTURE                              │  ← Overline
│                  How the AI Works                              │  ← Heading
│      Retrieval-Augmented Generation keeps answers              │  ← Subtext
│              grounded in real CVE data.                         │
│                                                                │
│                                                                │
│  ┌─────────┐     ┌─────────┐     ┌─────────┐                 │
│  │  SCAN   │────►│  EMBED  │────►│  STORE  │                 │
│  │ Docker  │     │Sentence │     │ChromaDB │                 │
│  │ + Trivy │     │Transform│     │Vector DB│                 │  ← Pipeline Row 1
│  └─────────┘     └─────────┘     └─────────┘                 │     (Ingestion phase)
│                                       │                        │
│                                       │ stored                 │
│                                       ▼                        │
│  ┌─────────┐     ┌─────────┐     ┌─────────┐                 │
│  │  QUERY  │────►│RETRIEVE │────►│GENERATE │                 │
│  │ User    │     │ Top 5   │     │ Ollama  │                 │
│  │Question │     │ by sim. │     │ LLM     │                 │  ← Pipeline Row 2
│  └─────────┘     └─────────┘     └─────────┘                 │     (Query phase)
│                                       │                        │
│                                       ▼                        │
│                                 ┌───────────┐                  │
│                                 │ AI Answer │                  │
│                                 │ grounded  │                  │
│                                 │ in data   │                  │
│                                 └───────────┘                  │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

**Node details:**

| Node | Icon Suggestion | Label | Sublabel |
|------|----------------|-------|----------|
| 1 | Docker whale | SCAN | Trivy scans image, outputs JSON with every CVE |
| 2 | Cpu/brain | EMBED | Sentence-Transformers converts each CVE to a 384-dim vector |
| 3 | Database cylinder | STORE | ChromaDB persists vectors for fast semantic search |
| 4 | MessageCircle | QUERY | User asks a question in natural language |
| 5 | Search | RETRIEVE | Cosine similarity finds the 5 most relevant CVEs |
| 6 | Sparkles | GENERATE | Ollama LLM (llama3.1:8b) generates a grounded answer |

**Connecting lines:**
- Solid lines with subtle animated gradient (a dot of accent-glow light traveling along the line, slowly, looping).
- Lines between Row 1 and Row 2 should show data flowing DOWN from STORE to RETRIEVE (these two share the vector database).

**Exact copy:**
- Overline: `ARCHITECTURE`
- Heading: `How the AI Works`
- Subtext: `Retrieval-Augmented Generation keeps answers grounded in real CVE data.`

**Mobile wireframe:**
```
┌──────────────────────┐
│                        │
│     ARCHITECTURE       │
│   How the AI Works     │
│                        │
│     ┌──────────┐      │
│     │   SCAN   │      │
│     └────┬─────┘      │
│          │             │
│          ▼             │
│     ┌──────────┐      │
│     │  EMBED   │      │
│     └────┬─────┘      │
│          │             │
│          ▼             │
│     ┌──────────┐      │
│     │  STORE   │      │
│     └────┬─────┘      │
│          │             │
│          ▼             │
│     ┌──────────┐      │
│     │  QUERY   │      │
│     └────┬─────┘      │
│          │             │
│          ▼             │
│     ┌──────────┐      │
│     │ RETRIEVE │      │
│     └────┬─────┘      │
│          │             │
│          ▼             │
│     ┌──────────┐      │
│     │ GENERATE │      │
│     └──────────┘      │
│                        │
└──────────────────────┘
```

Nodes stack vertically, connected by straight vertical lines with the same animation.

---

### SECTION 5: LIVE DEMO

**Purpose:** "See it actually working." Builds trust and looks impressive.

**Section ID:** `#demo`

**Desktop wireframe:**
```
┌──────────────────────────────────────────────────────────────┐
│                                                                │
│                      LIVE DEMO                                 │
│                  See It in Action                              │
│                                                                │
│  ┌─── Terminal Block (full width, max 900px) ──────────────┐  │
│  │ ● ● ●                        consec                     │  │
│  │─────────────────────────────────────────────────────────│  │
│  │                                                           │  │
│  │  $ consec check Dockerfile                               │  │
│  │                                                           │  │
│  │  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓  │  │
│  │  ┃          Dockerfile Security Findings (3)          ┃  │  │
│  │  ┣━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫  │  │
│  │  ┃ Rule    ┃ Severity ┃ Issue                         ┃  │  │
│  │  ┡━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩  │  │
│  │  │ CSC-001 │ HIGH     │ Unpinned base: node:latest    │  │  │
│  │  │ CSC-002 │ HIGH     │ No USER directive (runs root)  │  │  │
│  │  │ CSC-006 │ HIGH     │ Secret in ENV: DB_PASSWORD     │  │  │
│  │  └─────────┴──────────┴───────────────────────────────┘  │  │
│  │                                                           │  │
│  │  ✗ 3 findings (3 HIGH). Fix before deploying.            │  │
│  │                                                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌──────┐  ┌──────────┐  ┌─────────────┐                     │  ← Command tabs
│  │check │  │  scan    │  │  query      │                     │     (switch between
│  │(active)│ │          │  │             │                     │      3 demo outputs)
│  └──────┘  └──────────┘  └─────────────┘                     │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

**Three demo tabs (user clicks to switch which command is shown):**

**Tab 1 — `check` (default/active):**
```
$ consec check Dockerfile

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃          Dockerfile Security Findings (3)          ┃
┣━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Rule    ┃ Severity ┃ Issue                          ┃
┡━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CSC-001 │ HIGH     │ Unpinned base: node:latest     │
│ CSC-002 │ HIGH     │ No USER directive (runs root)  │
│ CSC-006 │ HIGH     │ Secret in ENV: DB_PASSWORD     │
└─────────┴──────────┴────────────────────────────────┘

✗ 3 findings (3 HIGH). Fix before deploying.
```

**Tab 2 — `scan`:**
```
$ consec scan nginx:latest

Scanning nginx:latest with Trivy...

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃           Vulnerability Summary                    ┃
┣━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┫
┃ CVE             ┃ Severity ┃ Package              ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩
│ CVE-2024-6119   │ HIGH     │ libssl3              │
│ CVE-2024-5535   │ MEDIUM   │ libssl3              │
│ CVE-2024-2511   │ LOW      │ libssl3              │
│ CVE-2023-6129   │ MEDIUM   │ libssl3              │
└─────────────────┴──────────┴──────────────────────┘

Found 4 vulnerabilities (1 HIGH, 2 MEDIUM, 1 LOW)
```

**Tab 3 — `query`:**
```
$ consec query "How do I fix CVE-2024-6119?"

Searching knowledge base...
Found 5 relevant documents.

CVE-2024-6119 is a certificate verification bypass in
OpenSSL 3.x. It affects the libssl3 package (installed:
3.0.11-1~deb12u2).

Remediation:
  1. Update libssl3 to version 3.3.2 or later
  2. Rebuild your container image with updated base
  3. Run: consec scan <image> to verify the fix
```

**Exact copy:**
- Overline: `LIVE DEMO`
- Heading: `See It in Action`
- No subtext needed — the terminal IS the content.

**Tab styling:** Tabs sit below the terminal. Active tab has accent-colored bottom border and text. Inactive tabs are text-muted. Clicking a tab swaps the terminal content (with a subtle fade transition, 200ms).

**Animation:** Optional typing effect on first view — text appears character by character in the terminal. After the animation completes once, content is static (no repeating).

**Mobile:** Terminal block goes full-width with horizontal scroll if needed. Tabs stack or become a horizontal scrollable row.

---

### SECTION 6: SECURITY RULES

**Purpose:** Showcase the 10 static analysis rules. Shows depth and rigor.

**Section ID:** `#rules`

**Desktop wireframe:**
```
┌──────────────────────────────────────────────────────────────┐
│                                                                │
│                    STATIC ANALYSIS                             │
│              10 Built-in Security Rules                        │
│     Deterministic checks — no AI required, instant results.    │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ CSC-001   [● HIGH]   Unpinned or :latest base images  ▼ │  │
│  │──────────────────────────────────────────────────────────│  │
│  │ CSC-002   [● HIGH]   Running as root user             ▼ │  │
│  │──────────────────────────────────────────────────────────│  │
│  │ CSC-003   [● MED ]   Missing HEALTHCHECK instruction  ▼ │  │
│  │──────────────────────────────────────────────────────────│  │
│  │ CSC-004   [● MED ]   Broad COPY . (entire context)    ▼ │  │
│  │──────────────────────────────────────────────────────────│  │
│  │ CSC-005   [● LOW ]   apt cache not cleaned in layer   ▼ │  │
│  │──────────────────────────────────────────────────────────│  │
│  │ CSC-006   [● HIGH]   Secrets hardcoded in ENV         ▼ │  │
│  │──────────────────────────────────────────────────────────│  │
│  │ CSC-007   [● LOW ]   ADD used instead of COPY         ▼ │  │
│  │──────────────────────────────────────────────────────────│  │
│  │ CSC-008   [● MED ]   SSH port (22) exposed            ▼ │  │
│  │──────────────────────────────────────────────────────────│  │
│  │ CSC-009   [● MED ]   Pipe-to-shell (curl | sh)        ▼ │  │
│  │──────────────────────────────────────────────────────────│  │
│  │ CSC-010   [● LOW ]   No multi-stage build             ▼ │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

**All 10 rules with their expanded content:**

| Rule | Severity | Title | Bad Example | Fixed Example | Why |
|------|----------|-------|-------------|---------------|-----|
| CSC-001 | HIGH | Unpinned or `:latest` base images | `FROM node:latest` | `FROM node:20.11.1` | Unpinned images change unexpectedly, introducing new vulnerabilities. |
| CSC-002 | HIGH | Running as root user | *(no USER directive)* | `USER nonroot:nonroot` | Root in a container means root-level access if a breakout occurs. |
| CSC-003 | MEDIUM | Missing HEALTHCHECK instruction | *(no HEALTHCHECK)* | `HEALTHCHECK CMD curl -f http://localhost/ \|\| exit 1` | Orchestrators can't detect unhealthy containers without a health check. |
| CSC-004 | MEDIUM | Broad `COPY .` (entire build context) | `COPY . /app` | `COPY package.json /app/`<br>`COPY src/ /app/src/` | Copies secrets, git history, node_modules — anything in the build context. |
| CSC-005 | LOW | apt cache not cleaned in same layer | `RUN apt-get update`<br>`RUN apt-get install -y curl` | `RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*` | Leftover cache bloats image size unnecessarily. |
| CSC-006 | HIGH | Secrets hardcoded in ENV | `ENV DB_PASSWORD=hunter2` | `# Use Docker secrets or runtime --env` | Secrets in image layers are visible to anyone with image access. |
| CSC-007 | LOW | ADD used instead of COPY | `ADD ./config /app/config` | `COPY ./config /app/config` | ADD has implicit tar extraction and URL fetch — unexpected behavior. |
| CSC-008 | MEDIUM | SSH port (22) exposed | `EXPOSE 22` | `# Remove SSH, use: docker exec -it <id> sh` | SSH in containers is an unnecessary attack surface. |
| CSC-009 | MEDIUM | Pipe-to-shell (`curl \| sh`) | `RUN curl -sL https://example.com/install.sh \| bash` | `RUN curl -sL -o install.sh https://example.com/install.sh && sha256sum --check checksums.txt && bash install.sh` | Piping to shell executes unverified code. |
| CSC-010 | LOW | No multi-stage build | Single `FROM` with build tools in final image | `FROM node:20 AS builder`<br>`...`<br>`FROM node:20-slim`<br>`COPY --from=builder /app /app` | Build tools in production increase attack surface and image size. |

**Exact copy:**
- Overline: `STATIC ANALYSIS`
- Heading: `10 Built-in Security Rules`
- Subtext: `Deterministic checks — no AI required, instant results.`

**Design:** The whole rules list sits inside a single `surface` card with border-subtle. Each row is separated by a 1px border-subtle line. Expanded content slides down smoothly (height transition 300ms). Only one row expanded at a time (accordion behavior — opening one closes the previous).

**Mobile:** Same layout, works naturally since it's a vertical list.

---

### SECTION 7: METRICS

**Purpose:** Quick impressive numbers. Scannable at a glance.

**Desktop wireframe:**
```
┌──────────────────────────────────────────────────────────────┐
│                                                                │
│                     BY THE NUMBERS                             │
│                                                                │
│   ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐  ┌──────┐  │
│   │ 1,500+ │  │  100+  │  │   10   │  │   7    │  │  $0  │  │
│   │ lines  │  │ tests  │  │ rules  │  │ cmds   │  │ cost │  │
│   │of code │  │written │  │built-in│  │  in    │  │cloud │  │
│   │        │  │        │  │        │  │  CLI   │  │ APIs │  │
│   └────────┘  └────────┘  └────────┘  └────────┘  └──────┘  │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

**Exact metrics:**

| Number | Label (line 1) | Label (line 2) |
|--------|---------------|---------------|
| `1,500+` | lines of | source code |
| `100+` | tests | written |
| `10` | security | rules |
| `7` | CLI | commands |
| `$0` | cloud API | cost |

**Styling:**
- Numbers: stat-number size (64px desktop / 40px mobile), bold, text-primary
- `$0` gets accent color instead of text-primary (highlight the zero-cost angle)
- Labels: stat-label size, text-secondary
- Numbers count up from 0 when scrolled into view (IntersectionObserver trigger)
- No cards/backgrounds — numbers float on the section background
- Overline: `BY THE NUMBERS` (no heading or subtext needed — the numbers speak)

**Mobile:** 2 columns, 3 rows. Or 3 + 2 layout.

---

### SECTION 8: TECH STACK

**Purpose:** Show the technologies used. Adds credibility.

**Desktop wireframe:**
```
┌──────────────────────────────────────────────────────────────┐
│                                                                │
│                      BUILT WITH                                │
│                                                                │
│  [Python] [Typer] [Rich] [Pydantic] [ChromaDB] [LangChain]   │
│                                                                │
│  [Ollama] [Sentence-Transformers] [Docker] [Trivy]            │
│                                                                │
│  [GitHub Actions] [pytest]                                     │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

**Each logo item:**
- Technology logo/icon (32x32 or 40x40) — use official SVG logos where possible, or simple text-icon fallbacks
- Technology name below (12px, text-secondary)
- Default state: grayscale, 50% opacity
- Hover: full color, 100% opacity, slight scale(1.05)
- Layout: flex-wrap, centered, gap 40px between items
- Optional: slow infinite horizontal scroll animation (marquee-style) instead of static grid

**Overline only:** `BUILT WITH` — no heading or subtext.

**Technologies to include (in this order):**
Python, Typer, Rich, Pydantic, ChromaDB, LangChain, Ollama, Sentence-Transformers, Docker, Trivy, GitHub Actions, pytest

**Mobile:** Same — logos wrap naturally.

---

### SECTION 9: GET STARTED (Installation)

**Purpose:** "This is easy to try." Final push to GitHub.

**Section ID:** `#install`

**Desktop wireframe:**
```
┌──────────────────────────────────────────────────────────────┐
│                                                                │
│                     QUICK START                                │
│                  Get Running in Seconds                        │
│                                                                │
│  ┌─── Terminal Block (max 700px, centered) ────────────────┐  │
│  │ ● ● ●                                                   │  │
│  │─────────────────────────────────────────────────────────│  │
│  │                                                           │  │
│  │  # Clone and install                                     │  │
│  │  $ git clone https://github.com/Vrohs/consec.git        │  │
│  │  $ cd consec && pip install -e ".[dev]"                  │  │
│  │                                                           │  │
│  │  # Scan an image                                         │  │
│  │  $ consec scan nginx:latest                              │  │
│  │                                                           │  │
│  │  # Check your Dockerfile                                 │  │
│  │  $ consec check Dockerfile                               │  │
│  │                                                           │  │
│  │  # Ask AI about vulnerabilities                          │  │
│  │  $ consec query "How do I fix CVE-2024-6119?"           │  │
│  │                                                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                │
│                   [ View on GitHub ➜ ]                          │  ← Primary CTA button
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

**Syntax coloring in the terminal block:**
- Comments (`#`): text-muted
- `$` prompt: accent color
- Command name (`consec`): text-primary, bold
- Arguments: text-secondary
- Strings (in quotes): accent at 70% opacity

**Exact copy:**
- Overline: `QUICK START`
- Heading: `Get Running in Seconds`
- Button: `View on GitHub ➜` — links to https://github.com/Vrohs/consec
- Terminal content: exactly as shown in wireframe above

**Mobile:** Terminal block full width. Button full width below.

---

### SECTION 10: FOOTER

**Purpose:** Credits, links, sign-off.

**Desktop wireframe:**
```
┌──────────────────────────────────────────────────────────────┐
│ ═══════════════ thin gradient line (accent) ════════════════ │
│                                                                │
│                      > consec_                                 │  ← Logo again, smaller
│                                                                │
│           Built by Advait · Chitkara University               │
│                    MIT License                                 │
│                                                                │
│                     [GitHub Icon]                               │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

**Exact copy:**
- Logo: `> consec_` (same styling as hero but 16px, accent color)
- Line 1: `Built by Advait · Chitkara University, Himachal Pradesh`
- Line 2: `MIT License`
- GitHub icon: links to https://github.com/Vrohs/consec
- All text: text-secondary, 14px
- Top border: 1px gradient line (accent fading to transparent on both ends)

**Background:** Darkest shade of bg-deep.

---

## Part 6: Visual Continuity (How Sections Flow Together)

This is CRITICAL. The page must feel like ONE continuous experience, not 10 separate blocks.

### Background Gradient Flow

The page background is NOT one solid color. It shifts subtly:

```
Hero:        bg-base (#0A0A0F) ─────────────────── solid
Problem:     bg-base → slight warm tint ─────────── barely perceptible
Features:    bg-deep (#12121A) ────────────────────  slightly darker
Architecture: bg-deep with very faint accent-glow ─ radial glow behind pipeline
Demo:        bg-base ──────────────────────────────  back to lighter
Rules:       bg-deep ──────────────────────────────  darker again
Metrics:     bg-base ──────────────────────────────  lighter
Tech Stack:  bg-base ──────────────────────────────  same
Install:     bg-deep ──────────────────────────────  darker
Footer:      darkest (#08080D) ────────────────────  end
```

Each shift is a CSS gradient that spans the full section height — there are NO hard lines between sections.

### Dot Grid Pattern

A subtle dot grid spans the ENTIRE page background (not per-section). Dots are 1px circles, `text-muted` at 10% opacity, spaced 40px apart. The grid is fixed-position (doesn't scroll with content — creates a subtle parallax). It fades out over the Architecture and Demo sections (where the content is dense) and fades back in for Metrics and below.

### Section Spacing Rhythm

- Between Hero and Problem: 0px (hero gradient bleeds into problem)
- Between all other sections: `section-padding-y` (120px desktop / 80px mobile) of empty space above each section's content
- Each section's internal content is vertically centered within its allocated space

---

## Part 7: Interactions & Animations

All animations use CSS transforms and opacity ONLY (GPU-accelerated). No layout-thrashing properties (height, width, margin) except for the accordion expand which uses max-height with overflow hidden.

| Element | Trigger | Animation | Duration |
|---------|---------|-----------|----------|
| All section headers + content | Scroll into viewport (IntersectionObserver, threshold 0.1) | Fade up: opacity 0→1, translateY(30px→0) | 600ms ease-out |
| Feature cards | Scroll into viewport | Staggered fade-up: each card delays 100ms after previous | 400ms per card |
| Pipeline nodes | Scroll into viewport | Sequential: each node fades in left-to-right with 200ms delay | 500ms per node |
| Pipeline connecting lines | After nodes appear | Draw-in: lines grow from left to right (stroke-dashoffset) | 800ms |
| Pipeline light dot | Continuous after drawn | A small accent-glow circle travels along the connecting lines | 3000ms loop |
| Stat numbers | Scroll into viewport | Count up from 0 to final number | 1500ms ease-out |
| Terminal demo (first view only) | Scroll into viewport | Typing effect: characters appear one by one | ~3000ms total |
| Terminal demo tab switch | Click | Content: fade out (150ms) → fade in (150ms) | 300ms total |
| Rule row expand | Click | Content slides down: max-height 0→auto, opacity 0→1 | 300ms ease |
| Feature cards | Hover | translateY(-4px), shadow increases, border → border-glow | 200ms ease |
| Tech logos | Hover | Grayscale→color, opacity 0.5→1, scale 1→1.05 | 200ms ease |
| Nav bar | Scroll past hero | Fade in from top: opacity 0→1, translateY(-10px→0) | 300ms ease |
| Scroll indicator (hero) | Continuous | Gentle bounce: translateY(0→8px→0) | 2000ms loop |
| CTA buttons | Hover | Primary: brightness increase. Ghost: border→accent, text→accent | 150ms ease |

**Performance rule:** Every animation should be cancelable. If the user scrolls fast, don't queue up a chain of delayed animations — let them fire immediately or skip.

---

## Part 8: Responsive Behavior

### Desktop: 1200px+
- Content max-width: 1200px, centered
- Feature cards: 4-column top row + 3-column bottom row
- Problem/Solution: side-by-side (2 equal columns)
- Pipeline: horizontal flow
- Metrics: single row of 5
- Nav: full horizontal links

### Tablet: 768px – 1199px
- Content max-width: 100% with 40px side padding
- Feature cards: 2 columns
- Problem/Solution: side-by-side but narrower
- Pipeline: horizontal but nodes shrink
- Metrics: 3 + 2 layout
- Nav: full horizontal links (smaller font)

### Mobile: < 768px
- Content: 100% with 20px side padding
- Feature cards: single column, full width
- Problem/Solution: stacked vertically (Problem on top)
- Pipeline: vertical flow (top to bottom)
- Metrics: 2 columns
- Terminal blocks: full width, horizontal scroll for overflow
- Nav: hamburger menu → dropdown overlay (bg-base at 95% opacity, full-screen)
- Buttons: full width, stacked vertically
- Section headings: smaller sizes as per typography table

---

## Part 9: Content Slots (Where Advait Plugs In)

These are the ONLY places where real tool output needs to be inserted:

| Slot | Location | What Goes Here | Format |
|------|----------|---------------|--------|
| Problem Left Panel | Section 2, left | Raw Trivy JSON output | Copy-paste JSON into code block |
| Problem Right Panel | Section 2, right | consec formatted table + AI explanation | Screenshot or HTML recreation |
| Demo Terminal (check) | Section 5, Tab 1 | Output of `consec check` on a sample Dockerfile | Copy-paste terminal output |
| Demo Terminal (scan) | Section 5, Tab 2 | Output of `consec scan` on an image | Copy-paste terminal output |
| Demo Terminal (query) | Section 5, Tab 3 | Output of `consec query` | Copy-paste terminal output |

**Everything else is static content already specified in this brief.** The designer should use the exact copy provided — Advait only needs to swap in real terminal screenshots/output in these 5 slots.

---

## Part 10: Deliverables Checklist

The designer should deliver:

1. **Figma file** with:
   - [ ] Complete page design at Desktop (1440px wide) breakpoint
   - [ ] Complete page design at Mobile (375px wide) breakpoint
   - [ ] Tablet (768px) at minimum for Problem/Solution and Features sections
   - [ ] All sections connected in one continuous frame (NOT separate pages)
   - [ ] Scroll behavior annotated (where sticky nav appears, where animations trigger)

2. **Component library** (in Figma):
   - [ ] Terminal Block (with 3 demo contents)
   - [ ] Feature Card (7 variants filled with content)
   - [ ] Severity Badge (4 variants: CRITICAL, HIGH, MEDIUM, LOW)
   - [ ] Rule Row (collapsed + expanded states)
   - [ ] Section Header
   - [ ] CTA Button (primary + ghost, default + hover states)
   - [ ] Stat Counter
   - [ ] Pipeline Node
   - [ ] Nav Bar (desktop + mobile states)

3. **Assets**:
   - [ ] consec logo/wordmark SVG (`> consec_` styled)
   - [ ] Favicon (16x16, 32x32)
   - [ ] 7 feature icons (can be from Lucide, Phosphor, or custom)
   - [ ] 6 pipeline node icons

4. **Style guide page**:
   - [ ] Color tokens with hex values
   - [ ] Typography scale
   - [ ] Spacing scale
   - [ ] Border radius values
   - [ ] Shadow values

---

## Part 11: What NOT to Do

- **DO NOT** design sections as separate pages or artboards — this is ONE continuous scrolling page
- **DO NOT** use stock photos, illustrations of people, or generic security imagery
- **DO NOT** use white or light backgrounds anywhere — the entire page is dark
- **DO NOT** add a pricing section, testimonials, or newsletter signup — this is a project showcase, not SaaS
- **DO NOT** add more sections than specified — 10 sections is the complete page
- **DO NOT** make the terminal blocks look fake — they should look like real macOS/Linux terminal windows
- **DO NOT** use Comic Sans, Papyrus, or any decorative fonts — stick to Inter + JetBrains Mono
- **DO NOT** add auto-playing sound or video

---

## Part 12: Reference Sites

Study these for visual language (not for content or structure):

| Site | What to study |
|------|--------------|
| https://linear.app | Dark theme, section transitions, typography hierarchy |
| https://warp.dev | Terminal aesthetic, developer-focused tone |
| https://vercel.com | Gradient usage, confident spacing, CTA placement |
| https://charm.sh | CLI tool branding, terminal mockups |
| https://railway.app | Dark surfaces, glowing accents, card design |
