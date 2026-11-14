// @ts-check
import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import press from "@fumapress/astro";

export default defineConfig({
  // the URL where your site is deployed, needed for SEO features like sitemap:
  // site: "https://example.com",
  integrations: [
    press({
      collections: { docs: { dir: "content" } },
      lastModified: true,
      includeProcessedMarkdown: true,
    }),
  ],
  vite: {
    plugins: [tailwindcss()],
  },
});
