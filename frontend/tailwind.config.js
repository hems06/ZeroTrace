/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        trust: {
          50: "#eef5fb",
          100: "#d6e8f5",
          600: "#0b6fab",
          700: "#0b3d59",
          900: "#071f30",
        },
      },
    },
  },
  plugins: [],
};
