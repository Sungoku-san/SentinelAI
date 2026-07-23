/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#0A0F1D",
          card: "#131C31",
          border: "#1E2D4A",
          text: "#F8FAFC",
          muted: "#94A3B8",
          primary: "#06B6D4",      # Cyan
          secondary: "#8B5CF6",    # Purple
          accent: "#EF4444",       # Red
          success: "#10B981"       # Green
        }
      }
    },
  },
  plugins: [],
}
