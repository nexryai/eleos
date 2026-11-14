import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

const locales = ["en", "ja", "zh-CN"];
const pages = [
  "index", "installation", "getting-started", "configuration",
  "networking", "cli", "troubleshooting",
];
const read = (path) => readFile(new URL(`../${path}`, import.meta.url), "utf8");
const url = (locale, page) => `/${locale}${page === "index" ? "" : `/${page}`}`;
const htmlPath = (locale, page) => `dist${url(locale, page)}/index.html`;
const codeBlocks = (text) => [...text.matchAll(/^```[^\n]*\n[\s\S]*?^```/gm)].map(([block]) => block);

test("all locales have the same pages, sidebar order and executable examples", async () => {
  const english = Object.fromEntries(await Promise.all(pages.map(async (page) => [
    page, codeBlocks(await read(`content/en/${page}.mdx`)),
  ])));
  for (const locale of locales) {
    const files = await readdir(new URL(`../content/${locale}/`, import.meta.url));
    assert.deepEqual(files.filter((file) => file.endsWith(".mdx")).sort(), pages.map((page) => `${page}.mdx`).sort());
    assert.deepEqual(JSON.parse(await read(`content/${locale}/meta.json`)).pages, pages);
    for (const page of pages) {
      const source = await read(`content/${locale}/${page}.mdx`);
      assert.match(source, /^---\ntitle: .+\ndescription: .+\n---\n/);
      assert.deepEqual(codeBlocks(source), english[page], `${locale}/${page}: example drift`);
      assert.doesNotMatch(source, /\[\[(?:baseline|inbound|outbound|security|router|custom|nat|apt|dnf|arch|snap|source)\]\]/);
      const prose = source.replace(/^```[^\n]*\n[\s\S]*?^```/gm, "");
      for (const [, target] of prose.matchAll(/\]\((\/[^)#]+)(?:#[^)]*)?\)/g)) {
        assert.ok(pages.some((slug) => url(locale, slug) === target), `${locale}/${page}: invalid or cross-language link ${target}`);
      }
    }
  }
});

test("each page has the correct language, alternates and Notebook top bar", async () => {
  const searchLabels = { en: "Search", ja: "検索", "zh-CN": "搜索" };
  for (const locale of locales) {
    for (const page of pages) {
      const html = await read(htmlPath(locale, page));
      assert.match(html, new RegExp(`<html[^>]+lang="${locale}"`));
      assert.match(html, /id="nd-notebook-layout"/);
      const header = html.match(/<header\b[^>]*id="nd-subnav"[\s\S]*?<\/header>/)?.[0];
      assert.ok(header, `${locale}/${page}: missing header`);
      assert.match(header, /href="https:\/\/github\.com\/nexryai\/eleos"/);
      assert.ok(header.includes(searchLabels[locale]), `${locale}/${page}: missing localized search`);
      assert.match(header, /aria-label="(?:Choose a language|言語を選択|选择语言)"/);
      assert.ok(html.includes("grid-template:&quot;. header header header .&quot;"), `${locale}/${page}: navigation is not above the sidebar`);
      for (const other of locales) {
        assert.ok(html.includes(`hreflang="${other}" href="${url(other, page)}"`), `${locale}/${page}: missing alternate ${other}`);
      }
    }
  }
  assert.match(await read("dist/index.html"), /http-equiv="refresh" content="\d+;url=\/en"/);
});

test("generated navigation and search indexes stay within their language", async () => {
  const trees = await readdir(new URL("../dist/_fumapress/page-tree/", import.meta.url));
  const search = JSON.parse(await read("dist/api/search.json"));
  assert.equal(search.type, "i18n");
  assert.deepEqual(Object.keys(search.raw).sort(), [...locales].sort());
  for (const locale of locales) {
    const filename = trees.find((name) => name.startsWith(`${locale}.`));
    assert.ok(filename, `missing ${locale} navigation`);
    const tree = JSON.parse(await read(`dist/_fumapress/page-tree/${filename}`));
    assert.deepEqual(tree.data.children.map((node) => node.url), pages.map((page) => url(locale, page)));
    const serialized = search.raw[locale]["1.doc"];
    assert.ok(serialized, `missing ${locale} search documents`);
    const documents = JSON.parse(serialized).map(([, document]) => document);
    assert.ok(documents.every((document) => document.locale === locale));
    for (const page of pages) {
      assert.ok(documents.some((document) => document.type === "page" && document.url === url(locale, page)), `${locale}/${page}: missing search entry`);
    }
  }
});
