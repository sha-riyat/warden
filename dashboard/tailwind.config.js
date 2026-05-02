/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        void:   '#0A0A0A',
        abyss:  '#111113',
        slate:  '#1A1A1F',
        ash:    '#2A2A30',
        bone:   '#E8E6E0',
        mist:   '#9A9890',
        fog:    '#4A4A54',
        signal: '#4A4AFF',
        pending:'#FFB800',
      },
      fontFamily: {
        sans:  ['Geist', 'system-ui', 'sans-serif'],
        mono:  ['Geist Mono', 'JetBrains Mono', 'monospace'],
        serif: ['DM Serif Display', 'Georgia', 'serif'],
      },
    },
  },
  plugins: [],
}
