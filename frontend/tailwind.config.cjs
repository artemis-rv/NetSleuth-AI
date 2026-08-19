/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#0a0f1c',
        surface: '#111827',
        'surface-elevated': '#1f2937',
        'border-subtle': '#374151',
        primary: '#f3f4f6',
        secondary: '#9ca3af',
        muted: '#6b7280',
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
