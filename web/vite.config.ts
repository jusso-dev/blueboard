import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// In development /api is proxied to the local Function App (func start --port 7351).
// In Azure, Static Web Apps routes /api to the linked Function App.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: { "/api": { target: "http://localhost:7351", changeOrigin: false } },
  },
  build: { outDir: "dist", sourcemap: false, target: "es2022" },
});
