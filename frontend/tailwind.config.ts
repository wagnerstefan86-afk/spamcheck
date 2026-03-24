import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        bg: {
          primary: "#0b0d14",
          secondary: "#111827",
          card: "#1a2035",
        },
        border: "#253049",
        accent: "#6366f1",
      },
    },
  },
  plugins: [],
};

export default config;
