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
    rolldownOptions: {
      output: {
        // Split the framework out of the app bundle. Roughly half of the
        // output is React + the router, which only changes when we bump those
        // deps; keeping them in their own chunks means a new agent-vault
        // release only invalidates the app chunk in the browser cache.
        codeSplitting: {
          groups: [
            {
              name: "vendor-react",
              test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/,
            },
            {
              name: "vendor-router",
              test: /node_modules[\\/]@tanstack[\\/]/,
            },
          ],
        },
      },
    },
  },
  server: {
    proxy: {
      "/v1": API_TARGET,
      "/discover": API_TARGET,
      "/health": API_TARGET,
      "/invite": API_TARGET,
    },
  },
});
