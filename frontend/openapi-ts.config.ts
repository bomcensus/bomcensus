// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import { defineConfig } from '@hey-api/openapi-ts'

export default defineConfig({
  input: '../api/openapi/admin.yaml',
  output: { path: 'app/api/gen' },
  plugins: [{ name: '@hey-api/client-fetch', baseUrl: '/api/v1' }, '@hey-api/typescript', '@hey-api/sdk'],
})
