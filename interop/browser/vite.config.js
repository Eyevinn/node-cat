import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
import path from 'path';

export default defineConfig({
  plugins: [nodePolyfills()],
  optimizeDeps: {
    include: ['@eyevinn/cat'],
    exclude: ['ioredis']
  },
  build: {
    commonjsOptions: {
      transformMixedEsModules: true,
      include: [/node_modules/, /..\/..\/lib/]
    }
  },
  resolve: {
    alias: {
      '@eyevinn/cat': '../../lib/index.js',
      ioredis: path.resolve(__dirname, './empty-module.js')
    }
  }
});
