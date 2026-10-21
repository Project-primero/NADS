import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  resolve: {
    extensions: ['.tsx', '.ts', '.jsx', '.js', '.json'],
  },
  cacheDir: '/tmp/nad-vite-cache',
  server: {
    port: 5174,
    strictPort: true,
    proxy: {
      '/api': { target: 'http://backend:8000', changeOrigin: true },
      '/ws':  { target: 'ws://backend:8000',  ws: true, changeOrigin: true },
    },
  },
});
