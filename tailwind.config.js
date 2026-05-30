/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/renderer/**/*.{html,js}"],
  theme: {
    extend: {
      colors: {
        void: "#050711",
        ink: "#0b1020",
        panel: "rgba(15, 23, 42, 0.66)",
        line: "rgba(148, 163, 184, 0.22)",
        cyanx: "#22d3ee",
        mintx: "#34d399",
        warnx: "#f59e0b",
        dangerx: "#fb7185"
      },
      boxShadow: {
        glass: "0 28px 80px rgba(0,0,0,.38)",
        glow: "0 0 42px rgba(34,211,238,.2)",
        danger: "0 0 40px rgba(251,113,133,.24)"
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["Cascadia Mono", "Consolas", "monospace"]
      }
    }
  },
  plugins: []
};
