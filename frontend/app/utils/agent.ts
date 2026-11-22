// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

import type { Agent } from '~/types'

/** Longest description the server accepts, in characters. */
export const agentDescriptionMax = 200

/**
 * Text of an agent in a select option: hostname, description and last peer address.
 * Agents may share a hostname (for example scanner pods), so the other two tell them apart.
 */
export const agentOptionLabel = (a: Agent) => [a.hostname, a.description, a.address].filter(Boolean).join(' · ')
