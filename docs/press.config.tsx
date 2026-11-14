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
    renderPage(props) {
      if (props.type === "docs") {
        return props.renderDefault({ layout: "notebook" });
      }
      return props.renderDefault();
    },
  },
});
