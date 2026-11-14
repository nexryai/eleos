import { getCollection } from "astro:content";
import { toFumadocsSource } from "@fumadocs/astro/source";
import { createPress } from "@fumapress/astro/config";

export default createPress(
  toFumadocsSource(await getCollection("docs"), await getCollection("meta")),
).config({
  site: {
    name: "docs",
  },
  ui: {
    layoutProps: {
      githubUrl: "https://github.com/nexryai/eleos",
    },
    renderPage(props) {
      return props.renderDefault({
        layout: "notebook",
        layoutProps: {
          nav: { mode: "top" },
        },
      });
    },
  },
});
