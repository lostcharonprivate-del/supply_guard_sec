import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    // Honour PORT so the dev server can be started on an assigned port.
    port: Number(process.env.PORT ?? 5173),
    // The dashboard talks to the API on the same origin in development, so
    // there are no CORS preflights and no API base URL to configure.
    proxy: {
      "/api": { target: process.env.VITE_API_TARGET ?? "http://localhost:8000", changeOrigin: true },
      "/health": { target: process.env.VITE_API_TARGET ?? "http://localhost:8000", changeOrigin: true },
    },
  },
  build: { outDir: "dist", sourcemap: true },
});
