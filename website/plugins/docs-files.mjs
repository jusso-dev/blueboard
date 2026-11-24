// Copies downloadable non-Markdown deliverables under docs/ (PDF, DOCX, architecture diagrams,
// banner, screenshots) into the built Docusaurus output directory so PDF/Word links resolve at
// /blueboard/Blueboard-*.pdf and /blueboard/architecture/azure-architecture.drawio.
import { cp, readdir } from "node:fs/promises";
import path from "node:path";

const SKIP_EXTENSIONS = new Set([".md", ".mdx", ".py", ".lua", ".yaml", ".yml", ".css", ".html"]);

async function copyTree(source, target) {
  for (const entry of await readdir(source, { withFileTypes: true })) {
    const from = path.join(source, entry.name);
    const to = path.join(target, entry.name);
    if (entry.isDirectory()) {
      await copyTree(from, to);
    } else {
      const ext = path.extname(entry.name).toLowerCase();
      if (!SKIP_EXTENSIONS.has(ext)) {
        await cp(from, to, { force: true });
      }
    }
  }
}

export default function docsFiles(context) {
  return {
    name: "blueboard-docs-files",
    async postBuild({ outDir }) {
      const docsRoot = path.resolve(context.siteDir, "../docs");
      await copyTree(docsRoot, outDir);
    }
  };
}
