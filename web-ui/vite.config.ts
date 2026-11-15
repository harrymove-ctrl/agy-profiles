import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

const selfHostedFontsCss = path.resolve(__dirname, "src/styles/self-hosted-fonts.css");
const emptyCss = path.resolve(__dirname, "src/styles/empty.css");

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@astryxdesign/theme-stone/fonts.css": selfHostedFontsCss,
      "@astryxdesign/theme-chocolate/fonts.css": emptyCss,
      "@astryxdesign/theme-gothic/fonts.css": emptyCss,
      "@astryxdesign/theme-matcha/fonts.css": emptyCss,
      "@astryxdesign/theme-neutral/fonts.css": emptyCss,
    },
  },
  esbuild: {
    charset: "ascii",
  },
  build: {
    outDir: "../src/agy_profiles/web_static",
    emptyOutDir: true,
    cssCodeSplit: false,
    assetsInlineLimit: 0,
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        inlineDynamicImports: true,
        assetFileNames: (assetInfo) => {
          const names = assetInfo.names || [];
          const fileName = names[0] || assetInfo.name || "";
          if (fileName.endsWith(".css")) {
            return "styles.css";
          }
          if (fileName.endsWith(".woff2") || fileName.endsWith(".woff")) {
            return "fonts/[name][extname]";
          }
          return "[name][extname]";
        },
      },
    },
  },
});
