/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#0a0a0b',
        surface: '#111113',
        'surface-elevated': '#1a1a1d',
        'border-subtle': '#2a2a2e',
        primary: '#e4e4e7',
        secondary: '#a1a1aa',
        muted: '#71717a',
        accent: '#3b82f6',
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444',
        info: '#3b82f6'
      }
    },
  },
  plugins: [],
}
