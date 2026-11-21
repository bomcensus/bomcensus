// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import { ApiError, getCurrentUser } from '~/api'

// Checks the session once per page load. Later 401s from any call also lead to /login (see ~/api/client.ts).
export default defineNuxtRouteMiddleware(async (to) => {
  const user = useCurrentUser()
  if (user.value === undefined) {
    try {
      user.value = await getCurrentUser()
    } catch (e) {
      // Anything but 401 (server unreachable, ...) leaves the state unknown: pages show their own load errors.
      if (e instanceof ApiError && e.status === 401) user.value = null
    }
  }
  if (to.path === '/login') {
    if (user.value) return navigateTo('/')
    return
  }
  if (user.value === null) return navigateTo({ path: '/login', query: { next: to.fullPath } })
})
