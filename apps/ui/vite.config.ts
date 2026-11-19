import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Built into apps/ui/dist and served by nginx (apps/ui/Dockerfile). In dev, /api
// is proxied to the API (API_URL, default http://127.0.0.1:8080).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "./",
  resolve: {
    alias: { "@": path.resolve(import.meta.dirname, "./src") },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    proxy: { "/api": process.env.API_URL ?? "http://127.0.0.1:8080" },
  },
});
