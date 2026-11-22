// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package collect

import (
	"os"
	"syscall"
)

func keyOf(fi os.FileInfo) (fileKey, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileKey{}, false
	}
	return fileKey{
		Dev:   uint64(st.Dev),
		Ino:   st.Ino,
		Size:  st.Size,
		Mtime: st.Mtim.Nano(),
		Ctime: st.Ctim.Nano(),
	}, true
}

func keyOfFile(_ *os.File, fi os.FileInfo) (fileKey, bool) { return keyOf(fi) }
