-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- Revoking an agent now marks its asset gone. Assets of agents revoked
-- before are marked gone as of the revocation.
UPDATE assets a SET gone_at = coalesce(g.revoked_at, now())
FROM agents g
WHERE a.agent_id = g.id AND g.state = 'revoked' AND a.gone_at IS NULL;

-- +goose Down
SELECT 1;
