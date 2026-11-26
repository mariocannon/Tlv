import { defineConfig } from "astro/config";

// Served from GitHub Pages at https://mariocannon.github.io/Tlv/ for now.
// On a custom domain, build with SITE_URL=https://yourdomain SITE_BASE=/ (see docs/DOMAIN.md).
export default defineConfig({
  site: process.env.SITE_URL ?? "https://mariocannon.github.io",
  base: process.env.SITE_BASE ?? "/Tlv/",
  build: { assets: "_astro" },
});
