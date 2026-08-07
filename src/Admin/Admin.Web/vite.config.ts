import { defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'node:fs';

export default defineConfig(({ mode, command }) => {
  const environment = loadEnv(mode, '.', '');
  const configuredTarget = process.env.VITE_ADMIN_PROXY_TARGET || environment.VITE_ADMIN_PROXY_TARGET;
  if (!configuredTarget && command === 'serve' && mode === 'development') throw new Error('VITE_ADMIN_PROXY_TARGET is required for the development server.');
  const proxyTarget = configuredTarget || 'https://development-proxy.invalid';
  const parsedTarget = new URL(proxyTarget);
  if (!['http:', 'https:'].includes(parsedTarget.protocol)) throw new Error('VITE_ADMIN_PROXY_TARGET must use HTTP or HTTPS.');
  const proxy = { target: proxyTarget, secure: true };
  const pfxPath = process.env.M5_ADMIN_DEV_HTTPS_PFX;
  const pfxPassword = process.env.M5_ADMIN_DEV_HTTPS_PFX_PASSWORD;
  const https = pfxPath && pfxPassword ? { pfx: readFileSync(pfxPath), passphrase: pfxPassword } : undefined;
  return {
    base: '/admin/',
    plugins: [react()],
    build: { outDir: 'dist', sourcemap: false, assetsDir: 'assets', emptyOutDir: true, chunkSizeWarningLimit: 600 },
    server: { host: '127.0.0.1', port: 5173, https, proxy: { '/admin/api': proxy, '/admin/auth': proxy } },
    test: { environment: 'jsdom', setupFiles: './src/test/setup.ts', css: true, include: ['src/**/*.test.{ts,tsx}', 'unit-tests/**/*.test.{ts,tsx}'] }
  };
});
