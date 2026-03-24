import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        bg: {
          primary: "#f5f5f7",
          secondary: "#ffffff",
          card: "#ffffff",
        },
        border: "#e5e5ea",
        accent: "#dc2626",
        "accent-hover": "#b91c1c",
        "text-primary": "#1d1d1f",
        "text-secondary": "#86868b",
        "text-tertiary": "#aeaeb2",
      },
      boxShadow: {
        card: "0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)",
        "card-hover": "0 4px 12px rgba(0,0,0,0.08), 0 2px 4px rgba(0,0,0,0.04)",
        float: "0 8px 30px rgba(0,0,0,0.08)",
        glow: "0 0 20px rgba(220,38,38,0.15)",
      },
      borderRadius: {
        "2xl": "1rem",
        "3xl": "1.5rem",
      },
      backdropBlur: {
        xl: "24px",
      },
    },
  },
  plugins: [],
};

export default config;
