// @ts-check
import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import press from "@fumapress/astro";
import { codeBlocks } from "./src/markdown.mjs";
import process from "node:process";

export default defineConfig({
  site: process.env.DOCS_SITE_URL,
  base: process.env.DOCS_BASE_PATH ?? "/",
  // Fumadocs handles highlighting after the Markdown tree is restored.
  markdown: { syntaxHighlight: false },
  integrations: [
    press({
      collections: { docs: { dir: "content" } },
      lastModified: true,
      includeProcessedMarkdown: true,
      ...codeBlocks,
    }),
  ],
  vite: {
    plugins: [tailwindcss()],
  },
});
