// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import tailwindcss from '@tailwindcss/vite'

// Server that `nuxt dev` forwards /api to. The built console is served by the server itself (same origin).
const apiServer = process.env.BOMCENSUS_API ?? 'http://localhost:8080'

export default defineNuxtConfig({
  compatibilityDate: '2026-07-01',
  ssr: false,
  devtools: { enabled: false },
  css: ['~/assets/css/main.css'],
  vite: {
    plugins: [tailwindcss()],
  },
  app: {
    head: {
      title: 'bomcensus',
      htmlAttrs: { lang: 'ko' },
      meta: [{ name: 'viewport', content: 'width=device-width, initial-scale=1' }],
    },
  },
  components: [{ path: '~/components', pathPrefix: false }],
  nitro: {
    // The mount prefix is stripped before forwarding, so the target repeats it.
    devProxy: { '/api': { target: `${apiServer.replace(/\/$/, '')}/api`, changeOrigin: true } },
  },
})
