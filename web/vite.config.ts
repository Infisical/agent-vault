import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const API_TARGET = process.env.VITE_API_URL ?? "http://localhost:14321";

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  base: "/",
  build: {
    outDir: "../internal/server/webdist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/v1": API_TARGET,
      "/proxy": API_TARGET,
      "/discover": API_TARGET,
      "/health": API_TARGET,
      "/invite": API_TARGET,
    },
  },
});
