import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// Base path is env-configurable so the same project builds for local dev,
// Vercel/Netlify (root), and GitHub Pages (subpath) without code changes:
//   VITE_BASE_PATH=/my-repo-name/ npm run build   (GitHub Pages)
//   npm run build                                 (root hosting / local)
const basePath = process.env.VITE_BASE_PATH || "/"

// https://vite.dev/config/
export default defineConfig({
  base: basePath,
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
})
