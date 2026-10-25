/** @type {import('tailwindcss').Config} */

/**
 * MULEGUARD design tokens.
 *
 * The palette is built for an investigative workbench, not a marketing site:
 * dense tables, long sessions, and judgement calls made from small numbers.
 *
 * Two deliberate decisions:
 *
 * 1. **Risk bands are not a traffic light.** LOW is slate, not green. A low
 *    score means "not prioritised", not "cleared", and green would tell an
 *    analyst the opposite. CRITICAL through MEDIUM run deep red, rust, amber —
 *    a heat ramp rather than a stop/go signal.
 *
 * 2. **Colour never carries meaning alone.** Every band and severity is
 *    rendered with its text label too. Roughly one in twelve men has a colour
 *    vision deficiency, and this is a tool where misreading a band matters.
 *
 * Dark mode is class-based (`.dark` on `<html>`) rather than media-based, so a
 * user's choice is respected over their operating system's.
 */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Neutral scale. Slightly blue-shifted so long sessions read cooler
        // than pure grey.
        ink: {
          50: '#f6f8fa',
          100: '#eceff3',
          200: '#d7dde5',
          300: '#b4bfcd',
          400: '#8b99ac',
          500: '#6b7a8f',
          600: '#546175',
          700: '#434e5f',
          800: '#2b3340',
          900: '#1a2029',
          950: '#111620',
        },
        // Restrained accent: navy, not a saturated blue. Used for primary
        // actions and the active nav state.
        accent: {
          50: '#eef4fb',
          100: '#d6e4f5',
          200: '#adc8ea',
          300: '#7ba5db',
          400: '#4d80c7',
          500: '#2f63ad',
          600: '#234e8c',
          700: '#1f4e79',
          800: '#1a3c5e',
          900: '#152d45',
        },
        risk: {
          critical: '#8c1d18',
          high: '#b3541e',
          medium: '#8a6d1f',
          low: '#546175',
          unknown: '#8b99ac',
        },
        severity: {
          critical: '#8c1d18',
          high: '#b3541e',
          medium: '#8a6d1f',
          low: '#546175',
        },
        state: {
          // Semantic feedback colours, distinct from the risk ramp so a
          // successful save never looks like a low-risk account.
          success: '#1f6f50',
          warning: '#9a6a12',
          danger: '#9f2d24',
          info: '#1f4e79',
        },
      },
      fontFamily: {
        sans: [
          'Inter var',
          'Inter',
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'sans-serif',
        ],
        // Identifiers, hashes, amounts and references are monospaced
        // throughout: an account id is compared character by character, and a
        // proportional font makes that harder than it needs to be.
        mono: [
          'JetBrains Mono',
          'SFMono-Regular',
          'Menlo',
          'Consolas',
          'Liberation Mono',
          'monospace',
        ],
      },
      fontSize: {
        // A dense table step below Tailwind's `xs`.
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
      },
      spacing: {
        // Table row height and sidebar width as named tokens, so layout code
        // does not hard-code them.
        row: '2.25rem',
        sidebar: '15rem',
        'sidebar-collapsed': '3.5rem',
      },
      boxShadow: {
        card: '0 1px 2px 0 rgb(17 22 32 / 0.04), 0 1px 3px 1px rgb(17 22 32 / 0.06)',
        panel: '0 4px 12px -2px rgb(17 22 32 / 0.10), 0 2px 6px -2px rgb(17 22 32 / 0.08)',
        'focus-accent': '0 0 0 2px rgb(47 99 173 / 0.45)',
      },
      borderRadius: {
        card: '0.5rem',
      },
      transitionDuration: {
        fast: '120ms',
      },
      keyframes: {
        'fade-in': {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        'slide-in-right': {
          from: { transform: 'translateX(100%)' },
          to: { transform: 'translateX(0)' },
        },
        shimmer: {
          '100%': { transform: 'translateX(100%)' },
        },
      },
      animation: {
        'fade-in': 'fade-in 120ms ease-out',
        'slide-in-right': 'slide-in-right 180ms cubic-bezier(0.32, 0.72, 0, 1)',
        shimmer: 'shimmer 1.4s infinite',
      },
    },
  },
  plugins: [],
};
