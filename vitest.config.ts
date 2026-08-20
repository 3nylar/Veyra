import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts", "api/tests/**/*.test.ts"],
    environment: "node",
  },
});
