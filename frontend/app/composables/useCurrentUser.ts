// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import type { Principal } from '~/types'

/** The logged-in user. undefined: not checked yet, null: no session. Set by the auth middleware and the login page. */
export const useCurrentUser = () => useState<Principal | null | undefined>('current-user', () => undefined)
