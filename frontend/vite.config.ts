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
      '/api': { target: process.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000', changeOrigin: true },
      '/ws':  { target: process.env.VITE_BACKEND_WS || 'ws://127.0.0.1:8000',  ws: true, changeOrigin: true },
    },
  },
});
