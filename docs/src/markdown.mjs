/** @type {import('@fumadocs/astro').CollectionOptions} */
export const codeBlocks = {
  mdastPlugins: [{
    name: "eleos-code-element",
    code(node, ctx) {
      // Satteri applies hName to the inner code element. Preserve its tag so
      // @fumadocs/astro's hide/restore-code plugins cannot turn it into a
      // second pre. Astro highlighting is disabled; Fumadocs highlights it.
      ctx.setProperty(node, "data", { ...node.data, hName: "code" });
    },
  }],
};
