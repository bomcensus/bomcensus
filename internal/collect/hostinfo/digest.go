// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package hostinfo

import (
	"strings"
	"unicode/utf8"

	"github.com/bomcensus/bomcensus/internal/report"
)

// maxValue bounds each reported string, in bytes.
const maxValue = 512

// clean trims s and cuts it to maxValue bytes. A rune split by the cut, or
// any other invalid UTF-8, is replaced with U+FFFD.
func clean(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxValue {
		s = s[:maxValue]
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\ufffd")
	}
	return s
}

// digestBody is HostSection without SectionMeta.
type digestBody struct {
	Hostname  string    `json:"hostname"`
	MachineID string    `json:"machine_id,omitempty"`
	OS        report.OS `json:"os"`
	Kernel    string    `json:"kernel,omitempty"`
	Arch      string    `json:"arch"`
}
