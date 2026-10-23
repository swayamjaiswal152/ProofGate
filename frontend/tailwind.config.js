/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#06080f",
        panel: "#0d1220",
        panel2: "#111a2e",
        edge: "#1e2a45",
        neon: "#39ff14",
        danger: "#ff3b5c",
        warn: "#ffb020",
        safe: "#00e39a",
        muted: "#8aa0c8",
      },
      fontFamily: {
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      boxShadow: {
        glow: "0 0 24px rgba(57,255,20,0.25)",
        danger: "0 0 24px rgba(255,59,92,0.3)",
      },
    },
  },
  plugins: [],
};
