import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: '/admin/',
  plugins: [react()],
  build: { outDir: 'dist', sourcemap: false, assetsDir: 'assets', emptyOutDir: true, chunkSizeWarningLimit: 600 },
  server: { host: '127.0.0.1', port: 5173, proxy: { '/admin/api': { target: 'https://localhost:8443', secure: true }, '/admin/auth': { target: 'https://localhost:8443', secure: true } } },
  test: { environment: 'jsdom', setupFiles: './src/test/setup.ts', css: true, include: ['src/**/*.test.{ts,tsx}', 'tests/**/*.test.{ts,tsx}'] }
});
