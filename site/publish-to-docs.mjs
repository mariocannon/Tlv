// Copies the built landing page into ../docs (GitHub Pages source) without touching
// the tap page (docs/t), the dashboard (docs/dashboard) or docs/config.js.
import { cpSync, rmSync, existsSync, readdirSync } from "node:fs";
const out = new URL("./dist/", import.meta.url), docs = new URL("../docs/", import.meta.url);
if (existsSync(new URL("_astro", docs))) rmSync(new URL("_astro", docs), { recursive: true });
for (const f of readdirSync(out)) cpSync(new URL(f, out), new URL(f, docs), { recursive: true });
console.log("Copied", readdirSync(out).join(", "), "into docs/");
