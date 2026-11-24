// Rewrites links from docs pages pointing to repository files outside docs/ (Bicep, C#, playbooks,
// templates, scripts) to GitHub blob links, and rewrites links to non-Markdown deliverables under
// docs/ (PDF, DOCX, DrawIO, images) to served paths under /blueboard/.
import { existsSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const DOCS = path.join(ROOT, "docs");
const REPO = "https://github.com/jusso-dev/blueboard/blob/main/";

export function rewrite(url, sourceFile) {
  if (!url || /^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith("//") || url.startsWith("/") || url.startsWith("#")) {
    return url;
  }
  const [pathPart, fragment] = url.split("#", 2);
  if (!pathPart) return url;
  const target = path.resolve(path.dirname(sourceFile), decodeURIComponent(pathPart));
  const insideRepo = target === ROOT || target.startsWith(ROOT + path.sep);
  const insideDocs = target === DOCS || target.startsWith(DOCS + path.sep);
  if (insideDocs) {
    if (!/\.mdx?$/i.test(target) && existsSync(target) && statSync(target).isFile()) {
      const relative = path.relative(DOCS, target).split(path.sep).map(encodeURIComponent).join("/");
      return "pathname:///blueboard/" + relative + (fragment ? "#" + fragment : "");
    }
    return url;
  }
  if (!insideRepo || !existsSync(target)) return url;
  const relative = path.relative(ROOT, target).split(path.sep).map(encodeURIComponent).join("/");
  return REPO + relative + (fragment ? "#" + fragment : "");
}

function visit(node, fn) {
  fn(node);
  for (const child of node.children ?? []) visit(child, fn);
}

export default function remarkSourceLinks() {
  return (tree, file) => {
    const source = file.path ?? file.history?.[0];
    if (!source) return;
    visit(tree, (node) => {
      if ((node.type === "link" || node.type === "definition") && typeof node.url === "string") {
        node.url = rewrite(node.url, source);
      }
    });
  };
}
