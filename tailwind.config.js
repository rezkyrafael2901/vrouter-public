/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: ['./templates/**/*.html'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['Azeret Mono', 'monospace'],
      },
      colors: {
        base: '#0F172A',
        surface: 'rgba(30,41,59,0.8)',
        elevated: 'rgba(51,65,85,0.8)',
        border: 'rgba(16,185,129,0.15)',
        primary: '#ffffff',
        secondaryText: '#94A3B8',
        muted: '#64748B',
        accent: '#10B981',
        'accent-bright': '#34D399',
        'accent-dark': '#059669',
      },
    },
  },
  plugins: [],
}
