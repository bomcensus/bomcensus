// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package collect

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the identity of a file (volume serial number and file index)
// is only available from an open handle, so a FileInfo alone is never
// keyed: Extra and SetExtra do not cache, and SHA256File keys by handle.
//
// The fields map as follows: Dev is the volume serial number, Ino the
// 64-bit file index, Mtime the last write time and Ctime the change time
// (FILE_BASIC_INFO.ChangeTime, updated on any data or metadata change), all
// times in 100 ns units since 1601.

func keyOf(os.FileInfo) (fileKey, bool) { return fileKey{}, false }

// fileBasicInfo is FILE_BASIC_INFO.
type fileBasicInfo struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
	FileAttributes                                          uint32
	_                                                       uint32
}

func keyOfFile(f *os.File, fi os.FileInfo) (fileKey, bool) {
	h := windows.Handle(f.Fd())
	var id windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &id); err != nil {
		return fileKey{}, false
	}
	var bi fileBasicInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&bi)), uint32(unsafe.Sizeof(bi))); err != nil {
		return fileKey{}, false
	}
	return fileKey{
		Dev:   uint64(id.VolumeSerialNumber),
		Ino:   uint64(id.FileIndexHigh)<<32 | uint64(id.FileIndexLow),
		Size:  fi.Size(),
		Mtime: bi.LastWriteTime,
		Ctime: bi.ChangeTime,
	}, true
}
