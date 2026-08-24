import { defineConfig } from 'vite';
import { crx } from '@crxjs/vite-plugin';
import manifest from './manifest.json';
import { cpSync, existsSync, mkdirSync } from 'fs';
import { resolve } from 'path';

export default defineConfig({
  plugins: [
    crx({ manifest }),
    {
      name: 'copy-model',
      closeBundle() {
        const src = resolve('assets/models');
        const dst = resolve('dist/assets/models');
        if (!existsSync(src)) return;
        mkdirSync(dst, { recursive: true });
        cpSync(src, dst, { recursive: true, dereference: true });
        // WASM from transformers package
        const wasmSrc = resolve('node_modules/onnxruntime-web/dist');
        const wasmDst = resolve('dist/assets');
        mkdirSync(wasmDst, { recursive: true });
        if (existsSync(wasmSrc)) {
          for (const f of ['ort-wasm.wasm', 'ort-wasm-simd.wasm', 'ort-wasm-threaded.wasm', 'ort-wasm-simd-threaded.wasm']) {
            const p = resolve(wasmSrc, f);
            if (existsSync(p)) cpSync(p, resolve(wasmDst, f));
          }
        }
      },
    },
  ],
  build: { outDir: 'dist', emptyOutDir: true },
});
