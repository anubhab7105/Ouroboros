import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

/**
 * MULEGUARD frontend build configuration.
 *
 * Notes on the choices here:
 *
 * - The dev server proxies `/api` to the backend rather than having the app
 *   call an absolute origin. That keeps the browser on one origin in
 *   development, so cookies and CORS behave the same as they do in production
 *   behind nginx.
 * - `VITE_API_BASE_URL` is read at build time for deployments where the API
 *   lives on a different host. It defaults to the same-origin `/api/v1`, which
 *   is what the bundled nginx config serves.
 * - Vendor chunks are split manually. Cytoscape and Recharts are large and
 *   change rarely, so isolating them means a normal application change does
 *   not invalidate them in a returning user's cache.
 * - Source maps are on in production builds. This is an internal investigative
 *   tool, not a public site; being able to read a real stack trace from a
 *   support report is worth more than hiding the source.
 */
export default defineConfig(({ mode }) => {
  const isProduction = mode === 'production';
  // Inside Docker Compose the API is reachable by service name; locally it is
  // on localhost. VITE_DEV_API_TARGET lets compose override it.
  const devApiTarget = process.env.VITE_DEV_API_TARGET ?? 'http://localhost:8000';

  // Ports come from the environment rather than from CLI arguments.
  //
  // `npm run dev -- --port 5173` is the documented way to forward an argument
  // to a script, and it does not survive PowerShell: `--` is PowerShell's own
  // end-of-parsing token, so it is stripped before npm sees it, npm then eats
  // `--port` as its own config, and vite receives a bare `5173` which it reads
  // as a positional project root:
  //
  //     Error: ENOENT: no such file or directory, lstat '...\frontend\5173'
  //
  // An environment variable has no quoting or forwarding behaviour to get
  // wrong, works the same in PowerShell, bash and Docker Compose, and matches
  // how VITE_DEV_API_TARGET above is already handled.
  const devPort = Number(process.env.VITE_DEV_PORT ?? 5173);
  const previewPort = Number(process.env.VITE_PREVIEW_PORT ?? 4173);

  return {
    plugins: [react()],

    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },

    server: {
      host: true, // listen on 0.0.0.0 so the container port mapping works
      port: devPort,
      strictPort: true,
      proxy: {
        '/api': {
          target: devApiTarget,
          changeOrigin: true,
          secure: false,
        },
      },
    },

    preview: {
      host: true,
      port: previewPort,
      strictPort: true,
    },

    build: {
      outDir: 'dist',
      sourcemap: true,
      target: 'es2022',
      // 900 kB: Cytoscape alone is comfortably over the 500 kB default, and a
      // warning that always fires is a warning nobody reads.
      chunkSizeWarningLimit: 900,
      rollupOptions: {
        output: {
          manualChunks: {
            'vendor-react': ['react', 'react-dom', 'react-router-dom'],
            'vendor-query': ['@tanstack/react-query', 'axios'],
            'vendor-graph': ['cytoscape', 'cytoscape-dagre', 'cytoscape-cose-bilkent'],
            'vendor-charts': ['recharts'],
          },
        },
      },
    },

    define: {
      __APP_BUILD_MODE__: JSON.stringify(mode),
      __APP_IS_PRODUCTION__: JSON.stringify(isProduction),
    },
  };
});
