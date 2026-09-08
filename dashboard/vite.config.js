import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxy REST + websocket to the FastAPI service so the dashboard talks to one origin.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true, rewrite: (p) => p.replace(/^\/api/, "") },
      "/ws": { target: "ws://127.0.0.1:8000", ws: true },
    },
  },
});
