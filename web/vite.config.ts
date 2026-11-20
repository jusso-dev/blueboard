import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Two entry points: the app, and the MSAL redirect bridge (/redirect), which must stay a separate, tiny page.
// In development /api is proxied to the local Function App (func start --port 7351) and auth is DEV_AUTH.
// In Azure the ASP.NET Core host (web/host) serves dist/ and the app calls the Function App directly.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: { "/api": { target: "http://localhost:7351", changeOrigin: false } },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    target: "es2022",
    rollupOptions: { input: { main: "index.html", redirect: "redirect.html" } },
  },
});
