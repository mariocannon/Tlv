import { defineConfig } from "astro/config";

// Served from GitHub Pages at https://mariocannon.github.io/Tlv/
export default defineConfig({
  site: "https://mariocannon.github.io",
  base: "/Tlv/",
  build: { assets: "_astro" },
});
