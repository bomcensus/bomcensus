-- Copyright (C) 2026 JC-Lab
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
-- Additional terms apply. See LICENSING.md.

-- +goose Up

-- The distribution's rating of a package match (vulnsvc.DistroRating),
-- empty when its advisories have none. It ranks the match instead of the
-- CVSS rating of the vulnerability.
ALTER TABLE component_vulns ADD COLUMN severity text NOT NULL DEFAULT ''
    CHECK (severity IN ('', 'critical', 'high', 'medium', 'low', 'negligible'));

-- Existing package matches get the rating of their advisories, as
-- vulnsvc.DistroRating computes it, so that they need no new match.
UPDATE component_vulns v SET severity = r.severity
FROM (
    SELECT x.component_id, x.vuln_id, x.method,
        (array_agg(x.rating ORDER BY x.rank DESC))[1] AS severity
    FROM (
        SELECT cv.component_id, cv.vuln_id, cv.method, m.rating, m.rank
        FROM component_vulns cv
        CROSS JOIN LATERAL jsonb_array_elements(cv.advisories) a
        JOIN (VALUES
            ('unimportant', 'negligible', 1), ('negligible', 'negligible', 1),
            ('low', 'low', 2), ('medium', 'medium', 3), ('moderate', 'medium', 3),
            ('high', 'high', 4), ('important', 'high', 4), ('critical', 'critical', 5)
        ) AS m (word, rating, rank) ON m.word = rtrim(lower(btrim(coalesce(a->>'severity', ''))), '*')
        WHERE cv.method = 'package'
    ) x
    GROUP BY x.component_id, x.vuln_id, x.method
) r
WHERE v.component_id = r.component_id AND v.vuln_id = r.vuln_id AND v.method = r.method;

-- +goose Down
ALTER TABLE component_vulns DROP COLUMN severity;
