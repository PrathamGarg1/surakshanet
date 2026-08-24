import { defineConfig } from 'vite';
import { crx } from '@crxjs/vite-plugin';
import manifest from './manifest.json';
import fs from 'fs';
import path from 'path';

function copyAssetsPlugin() {
  return {
    name: 'copy-assets',
    closeBundle() {
      const distDir = path.resolve('dist');
      const wasmSrc = path.resolve('node_modules/@xenova/transformers/dist');
      const wasmDest = path.resolve(distDir, 'assets');
      if (!fs.existsSync(wasmDest)) fs.mkdirSync(wasmDest, { recursive: true });
      if (fs.existsSync(wasmSrc)) {
        for (const file of fs.readdirSync(wasmSrc).filter((f) => f.endsWith('.wasm'))) {
          fs.copyFileSync(path.join(wasmSrc, file), path.join(wasmDest, file));
        }
      }
      const modelSrc = path.resolve('assets/models');
      const modelDest = path.resolve(distDir, 'assets/models');
      if (fs.existsSync(modelSrc)) {
        fs.cpSync(modelSrc, modelDest, { recursive: true, dereference: true });
      }
    },
  };
}

export default defineConfig({
  base: './',
  plugins: [crx({ manifest }), copyAssetsPlugin()],
  build: { outDir: 'dist', emptyOutDir: true },
});
