import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: '#0a0e17',
          card: '#111827',
          border: '#1e293b',
        },
        accent: {
          green: '#22c55e',
          cyan: '#06b6d4',
          red: '#ef4444',
          yellow: '#eab308',
          orange: '#f97316',
        },
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 15px rgba(34, 197, 94, 0.3)',
        'glow-cyan': '0 0 15px rgba(6, 182, 212, 0.3)',
        'glow-red': '0 0 15px rgba(239, 68, 68, 0.3)',
      },
      animation: {
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { boxShadow: '0 0 5px rgba(34, 197, 94, 0.3)' },
          '50%': { boxShadow: '0 0 20px rgba(34, 197, 94, 0.6)' },
        },
      },
    },
  },
  plugins: [],
};

export default config;
