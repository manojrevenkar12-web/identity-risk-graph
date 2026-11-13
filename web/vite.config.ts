import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/v1": "http://localhost:8080" } },
  test: { environment: "jsdom", globals: true, setupFiles: ["src/test/setup.ts"] },
});
