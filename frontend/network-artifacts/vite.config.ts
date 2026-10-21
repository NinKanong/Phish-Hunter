import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/static/network-artifacts/',
  build: { outDir: '../../phishhunter/web/static/network-artifacts', emptyOutDir: false, sourcemap: true },
});
