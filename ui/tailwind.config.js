/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Monochrome Elite Palette
        primary: {
          50: '#ffffff',
          100: '#fcfcfc',
          200: '#f5f5f5',
          300: '#e5e5e5',
          400: '#d4d4d4',
          500: '#a3a3a3',
          600: '#737373',
          700: '#525252',
          800: '#404040',
          900: '#262626',
          950: '#171717',
        },
        dark: {
          50: '#fafafa',
          100: '#f5f5f5',
          200: '#e5e5e5',
          300: '#d4d4d4',
          400: '#a3a3a3',
          500: '#737373',
          600: '#525252',
          700: '#404040',
          800: '#262626',
          900: '#171717',
          950: '#0a0a0a', // True deep black
        },
        slate: {
          950: '#020617',
        },
        surface: '#0a0a0a',
        accent: '#ffffff',
        success: '#22c55e',
        danger: '#ef4444',
        warning: '#f59e0b',
        info: '#3b82f6',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'monospace'],
        display: ['Outfit', 'Inter', 'sans-serif'],
      },
      boxShadow: {
        'glow': '0 0 20px rgba(255, 255, 255, 0.1)',
        'glow-white': '0 0 30px rgba(255, 255, 255, 0.2)',
        'glow-error': '0 0 20px rgba(239, 68, 68, 0.2)',
        'glow-success': '0 0 20px rgba(34, 197, 94, 0.2)',
        'premium': '0 20px 50px -12px rgba(0, 0, 0, 0.5)',
        'inner-glow': 'inset 0 0 20px rgba(255, 255, 255, 0.05)',
      },
      animation: {
        'fade-in': 'fadeIn 0.5s ease-out',
        'slide-up': 'slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1)',
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'shimmer': 'shimmer 2s linear infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { transform: 'translateY(20px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        shimmer: {
          '100%': { transform: 'translateX(100%)' },
        },
      },
      backdropBlur: {
        'premium': '20px',
      },
    },
  },
  plugins: [
    function({ addBase, theme }) {
      addBase({
        'body': {
          backgroundColor: '#0a0a0a',
          color: '#ffffff',
          fontFamily: theme('fontFamily.sans'),
          WebkitFontSmoothing: 'antialiased',
        },
        'h1, h2, h3, h4, h5, h6': {
          fontFamily: theme('fontFamily.display'),
          fontWeight: '700',
          letterSpacing: '-0.02em',
        },
      })
    },
  ],
}
