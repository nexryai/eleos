// @ts-check
import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import press from "@fumapress/astro";
import { codeBlocks } from "./src/markdown.mjs";

export default defineConfig({
  // Fumadocs handles highlighting after the Markdown tree is restored.
  markdown: { syntaxHighlight: false },
  // the URL where your site is deployed, needed for SEO features like sitemap:
  // site: "https://example.com",
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
