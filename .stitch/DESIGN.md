# Design System: WIREX

Premium cyber-tech VPN service. Mobile-first, dark, technical, no fluff.

## 1. Visual Theme & Atmosphere

**Vibe:** Linear-precision meets ProtonVPN-premium with a cyber-tech edge. Pure black canvas, single neon-cyan accent, surgical typography. Subtle ambient glow and grid hints — never noisy. Every pixel earned.

**Anti-vibe:** No cyberpunk noise (avoid scanlines, glitch artifacts, neon overload). No glassmorphism. No pill-shaped UI. No rainbow gradients.

**Tone:** Russian, terse, technical when it matters, friendly when it doesn't.

## 2. Color Palette & Roles

```
Background base       #000000   pure void, app canvas
Surface 1             #0A0A0A   raised cards, list rows
Surface 2             #111111   modals, deepest elevation
Border subtle         #1A1A1A   row dividers, low-noise edges
Border default        #2A2A2A   card borders, input idle
Border accent         #F5F5F5   focus, active, hover
Text primary          #F0F0F0   body, headlines
Text secondary        #8A8A8A   metadata, hints
Text tertiary         #4A4A4A   disabled, placeholders
Accent / Primary      #F5F5F5   primary CTA (filled), active states, links — monochrome
Accent dim            #CCCCCC   hover/pressed primary
Accent glow           rgba(245,245,245,.20)   ambient glow under key elements
Accent wash           rgba(245,245,245,.06)   tinted backgrounds
Status success        #00E78B   "active", connected
Status warning        #FFB020   "expiring soon"
Status danger         #FF4757   errors, deletions
```

Backgrounds layer dark→darker by elevation; the only light color in the system is the cyan accent.

## 3. Typography Rules

```
Display headlines    Space Grotesk, weight 600-700, tight tracking (-0.02em)
Body                 Inter, weight 400, normal tracking
Labels / micro       Inter, weight 500-600, uppercase, tracking +0.12em (caps)
Technical / mono     JetBrains Mono, weight 400-500 — for keys, URLs, codes
```

**Hierarchy:**
- H1 (page-level): 30/36px, weight 700, condensed
- H2 (section): 22/28px, weight 600
- H3 (card): 16/22px, weight 600
- Body: 14/20px (mobile default)
- Caption / metadata: 11/16px, secondary color, often uppercase
- Mono data: 13/18px

## 4. Component Stylings

### Buttons
- **Primary:** solid `#00EEFC` background, black text, weight 700, 14px font, 14px vertical padding, 8px radius, glow `0 0 24px rgba(0,238,252,.35)` on hover. Active state: `#00B8C4` bg.
- **Secondary:** transparent bg, 1px border `#2A2A2A`, text `#F0F0F0`, hover border becomes `#00EEFC`, no glow.
- **Tertiary / text:** no bg/border, text `#00EEFC`, underline on hover.
- **Destructive:** transparent bg, border + text `#FF4757`.
- All corners: **8px radius**. No pills (no `rounded-full`) anywhere except small status chips.

### Inputs
- 1px border `#2A2A2A` on `#0A0A0A` bg
- 14px vertical / 16px horizontal padding
- 8px radius
- Focus: border becomes `#00EEFC`, box-shadow `0 0 0 3px rgba(0,238,252,.12)` (focus ring)
- Mono-styled placeholder for technical fields (email, OTP, server URL display)

### Cards / Containers
- Bg `#0A0A0A`, border `#1A1A1A`, 12px radius
- Active/selected: border `#00EEFC`, slight wash `rgba(0,238,252,.04)`
- No box-shadows by default — depth comes from contrast, not blur

### Modals / Sheets
- Backdrop `rgba(0,0,0,.85)` with subtle blur (8px)
- Modal surface `#111111`, border `#2A2A2A`, 16px radius
- Bottom-sheet style on mobile (slide up from bottom for client picker)
- Top-right close button, 24px tap target

### Status chips (small)
- 11px font, uppercase, +0.12em tracking
- Pill (full radius — only here)
- "ACTIVE" → success bg-wash, text `#00E78B`
- "EXPIRING" → warning
- "INACTIVE" → border-only, text secondary

### Accordion (`<details>`)
- Chevron rotates 180°
- Summary: 14/20 caption-style label in cyan, monospace data inside
- 8px radius on the wrapper

### QR display
- White `#FFFFFF` 12px-padded inner, 12px radius outer card with cyan border (1px)
- ~200px on mobile

### Toast
- Bottom-anchored, slide-up animation, full-width with side margins on mobile
- Border-left 3px in status color, surface `#111111`

## 5. Layout Principles

- **Mobile-first**: base styles for 360-414px width. Desktop only as visual upscale (max-width container ~520px on auth/result screens).
- **Spacing scale**: 4 / 8 / 12 / 16 / 24 / 32 / 48 px. Avoid odd values.
- **Vertical rhythm**: 16px base gap between distinct UI atoms; 24px between section blocks; 32-48px before CTA.
- **Container padding**: 20px horizontal on mobile, 24px on tablet+.
- **Grid background**: optional decorative — 1px lines `#0A0A0A` on `#000000` at 32px tile, 30% opacity. Used on hero/login, NOT inside dense lists.
- **Glow accents**: reserved for the *single* most important action on screen. Don't sprinkle.

## 6. Iconography

- Material Symbols Outlined (matching current setup), weight 300-400 — keep them thin and technical
- Status / data icons: 18-20px
- Decorative / hero: up to 64px
- Color: `#F0F0F0` neutral, `#00EEFC` for active/highlighted

## 7. Brand Mark Usage

- Logo file: `/static/logo.svg` (1024×1024 with internal black bg)
- **Header**: 28-32px height, no extra background needed (logo carries its own black bg, blends with `#000`)
- **Login hero**: 80-96px, centered above tagline
- Wordmark "WIREX" beside small mark: optional, set in Space Grotesk weight 700, uppercase, +0.04em tracking

## 8. Key Screens — structural intent

1. **Login**: Logo (large) → "Подключение к WIREX" headline → email field → consent checkboxes (compact, two lines each max) → primary CTA full-width.
2. **OTP**: Same hero shrunk → 6 boxed digit inputs (mono) → resend timer text → tertiary "Изменить email" link.
3. **My Keys**: Header with email + logout → list of key cards (server flag • name • protocol chips • created date • copy/delete) → sticky bottom CTA "Создать ключ".
4. **Server picker**: Username field → server cards (flag • country • load chip • selected indicator) → bottom CTA.
5. **Result**: QR card (cyan-bordered) → primary "Начать использовать" → 3 collapsible accordions (key, sub, instructions) → tertiary "К моим ключам".
6. **Payment modal**: Subscription state header → 4 tariff cards in 2×2 grid → primary "Оплатить через lava.top" → divider → promo input.
