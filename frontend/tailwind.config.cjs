/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#08090b',
        surface: '#101216',
        'surface-elevated': '#15171c',
        'border-subtle': 'rgba(255, 255, 255, 0.08)',
        'border-subtle-2': 'rgba(255, 255, 255, 0.05)',
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
};
