/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0A0A0A",
        paper: "#FCF7EC",
        panel: "#FFFFFF",
        acid: "#C7FB4F",     // lime accent
        volt: "#FFE500",     // yellow
        cyan: "#4DE1FF",
        hot: "#FF5FA2",      // pink
        grape: "#9B6BFF",
        crit: "#FF4D4D",
        high: "#FF8A3D",
        med: "#FFC531",
        low: "#7BE38B",
      },
      fontFamily: {
        display: ["'Space Grotesk'", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
      },
      boxShadow: {
        brutal: "6px 6px 0 0 #0A0A0A",
        "brutal-sm": "3px 3px 0 0 #0A0A0A",
        "brutal-lg": "10px 10px 0 0 #0A0A0A",
        "brutal-acid": "6px 6px 0 0 #C7FB4F",
      },
      keyframes: {
        flow: { "0%": { strokeDashoffset: 24 }, "100%": { strokeDashoffset: 0 } },
        pop: { "0%": { transform: "scale(0.9)", opacity: 0 }, "100%": { transform: "scale(1)", opacity: 1 } },
        blink: { "0%,100%": { opacity: 1 }, "50%": { opacity: 0.25 } },
      },
      animation: {
        flow: "flow 0.8s linear infinite",
        pop: "pop 0.18s ease-out",
        blink: "blink 1.2s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
