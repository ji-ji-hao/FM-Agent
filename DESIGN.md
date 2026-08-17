# FM-Agent Viewer Design System

## 1. Atmosphere & Identity

FM-Agent Viewer is a dense, quiet security-analysis workstation. It favors evidence over decoration and keeps the existing IFC visual language: a charcoal three-pane shell, compact monospace typography, and semantic verdict colors. The signature interaction is progressive disclosure: a project verdict opens into candidate chains, then into functions, source, and raw reasoning.

## 2. Color

| Role | Token | Value | Usage |
|---|---|---|---|
| Surface/primary | `--bg` | `#0f1115` | Application background |
| Surface/panel | `--panel` | `#171a21` | Fixed shell regions |
| Surface/elevated | `--panel2` | `#1e222b` | Cards, controls, code |
| Border/default | `--border` | `#2a2f3a` | Dividers and outlines |
| Text/primary | `--fg` | `#e6e8eb` | Main content |
| Text/secondary | `--muted` | `#9aa3b2` | Metadata and hints |
| Accent/interactive | `--accent` | `#4f9dff` | Links, focus, selection |
| Status/vulnerable | `--vulnerable` | `#ff5c5c` | Confirmed conflict |
| Status/safe | `--safe` | `#3fcf8e` | Safe result |
| Status/review | `--review` | `#ffb454` | Incomplete premise |
| Status/error | `--error` | `#c678dd` | Analysis failure |

Color carries analysis state or interaction state only. New capability components reuse these tokens and do not introduce a second accent palette.

## 3. Typography

| Level | Size | Weight | Line height | Usage |
|---|---:|---:|---:|---|
| Panel title | 14px | 600 | 1.5 | Viewer and function headings |
| Section title | 12px | 600 | 1.5 | Collapsible section headers |
| Body | 13px | 400 | 1.5 | Default analysis text |
| Metadata | 11px | 400 | 1.4 | Paths, counts, evidence |
| Badge | 10px | 700 | 1.4 | Verdict and step kinds |

Primary and mono: `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`. The viewer intentionally uses one family because code, identifiers, and evidence dominate the interface.

## 4. Spacing & Layout

All spacing follows a 4px base: 4, 8, 12, 16, 20, 24, 32, and 40px.

- Shell: fixed header plus a `minmax(0, 1fr)` content row bounded by `100dvh`.
- Desktop: 290px function list, fluid detail pane, 420px reasoning pane.
- Tablet: reasoning pane moves below the detail pane.
- Mobile below 768px: one column; header wraps, list and detail become full-width regions, and primary content never scrolls horizontally.
- Scroll ownership: function list, detail pane, and reasoning pane each own their vertical scroll on desktop. Native document scroll owns the mobile layout.

## 5. Components

### Function Row
- Structure: verdict badge, function name, module, event count.
- States: default, hover, selected, keyboard focus.
- Layout: compact cluster inside the left list scroll owner.

### Verdict Badge
- Variants: `VULNERABLE`, `NEEDS_REVIEW`, `SAFE`, `ERROR`, plus existing plugin verdicts.
- Accessibility: color is paired with text; contrast follows WCAG AA.

### Analysis Section
- Structure: disclosure heading and body.
- States: expanded, collapsed, keyboard focus.
- Motion: instant under reduced motion; otherwise a short opacity transition only.

### Capability Project Overview
- Structure: verdict summary, analysis coverage, candidate-chain disclosures.
- States: loading, empty, vulnerable, review, safe, error.
- Layout: stack in the fluid detail pane.

### Candidate Chain
- Structure: chain number, seed, sink, confidence, compact critical path, expandable propagation hops.
- States: collapsed, expanded, keyboard focus.
- Accessibility: native `details/summary`; no information depends on color alone.

### Capability Path Step
- Structure: kind badge, function button, source, destination.
- Variants: seed, propagation, obligation, registration, dispatch, writeback.
- Content stress: identifiers wrap with `overflow-wrap:anywhere`; absent values render as `unknown`.

## 6. Motion & Interaction

- Motion intensity: 2/10. This is an operational analysis surface.
- Hover and focus feedback use color, border, opacity, or a 1px transform.
- No automatic animation, scroll hijacking, or perpetual motion.
- `prefers-reduced-motion` disables non-essential transitions.

## 7. Depth & Surface

Strategy: mixed tonal shift plus 1px borders. Panels are separated by surface tone and border; cards use `--panel2`. Only the existing modal uses a prominent shadow. Capability chains do not add decorative glows or new elevation levels.

## 8. Accessibility Constraints & Accepted Debt

### Constraints

- Target WCAG 2.2 AA.
- All actions are native buttons, links, or disclosure controls and are keyboard reachable.
- Every interactive element has a visible `:focus-visible` outline using `--accent`.
- Verdicts and path kinds include readable text, not color-only meaning.
- Long identifiers wrap; primary content has no horizontal overflow at 375px.
- The viewer respects `prefers-reduced-motion`.

### Accepted Debt

None for the capability viewer scope.
