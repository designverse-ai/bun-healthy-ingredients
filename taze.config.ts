import { defineConfig } from "taze"

export default defineConfig({
  force: false,
  write: true,
  install: true,
  ignorePaths: [
    "**/node_modules/**",
    "**/dist/**",
    "**/.cache/**",
    "**/.reports/**",
    "**/.atmos/**",
    "**/.trunk/**",
    "**/.git/**",
  ],
  ignoreOtherWorkspaces: true,
  concurrency: 20,
  all: false,
  group: true,
  includeLocked: true,
  interactive: true,
  nodecompat: true,
  recursive: true,
  maturityPeriod: 3,
})
