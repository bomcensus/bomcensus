// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sandbox

// Win32 declarations that golang.org/x/sys/windows does not have.

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	moduser32   = windows.NewLazySystemDLL("user32.dll")
	moduserenv  = windows.NewLazySystemDLL("userenv.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procIsProcessInJob = modkernel32.NewProc("IsProcessInJob")

	procCreateRestrictedToken                     = modadvapi32.NewProc("CreateRestrictedToken")
	procDeriveAppContainerSidFromAppContainerName = moduserenv.NewProc("DeriveAppContainerSidFromAppContainerName")
	procCreateAppContainerProfile                 = moduserenv.NewProc("CreateAppContainerProfile")
	procCreateWindowStationW                      = moduser32.NewProc("CreateWindowStationW")
	procCloseWindowStation                        = moduser32.NewProc("CloseWindowStation")
	procGetProcessWindowStation                   = moduser32.NewProc("GetProcessWindowStation")
	procSetProcessWindowStation                   = moduser32.NewProc("SetProcessWindowStation")
	procCreateDesktopW                            = moduser32.NewProc("CreateDesktopW")
	procCloseDesktop                              = moduser32.NewProc("CloseDesktop")
	procGetUserObjectInformationW                 = moduser32.NewProc("GetUserObjectInformationW")
)

// CreateRestrictedToken flags.
const disableMaxPrivilege = 0x1

// Process and thread attributes (ProcThreadAttributeValue in winbase.h).
const (
	procThreadAttributeHandleList                   = 0x00020002
	procThreadAttributeMitigationPolicy             = 0x00020007
	procThreadAttributeSecurityCapabilities         = 0x00020009
	procThreadAttributeJobList                      = 0x0002000D
	procThreadAttributeChildProcessPolicy           = 0x0002000E
	procThreadAttributeAllApplicationPackagesPolicy = 0x0002000F
	procThreadAttributeDesktopAppPolicy             = 0x00020012
)

const (
	processCreationChildProcessRestricted                = 0x01
	processCreationAllApplicationPackagesOptOut          = 0x01
	processCreationDesktopAppBreakawayDisableProcessTree = 0x01
)

// PROCESS_CREATION_MITIGATION_POLICY_* (first 64-bit word).
const (
	mitigationForceRelocateImagesAlwaysOn = 0x1 << 8
	mitigationHeapTerminateAlwaysOn       = 0x1 << 12
	mitigationBottomUpASLRAlwaysOn        = 0x1 << 16
	mitigationHighEntropyASLRAlwaysOn     = 0x1 << 20
	mitigationStrictHandleChecksAlwaysOn  = 0x1 << 24
	mitigationWin32kSystemCallDisableOn   = 0x1 << 28
	mitigationExtensionPointDisableOn     = 0x1 << 32
	mitigationProhibitDynamicCodeOn       = 0x1 << 36
	mitigationFontDisableOn               = 0x1 << 48
	mitigationImageLoadNoRemoteOn         = 0x1 << 52
	mitigationImageLoadNoLowLabelOn       = 0x1 << 56
	mitigationImageLoadPreferSystem32On   = 0x1 << 60
)

// Window station and desktop.
const cwfCreateOnly = 0x1

// JOB_OBJECT_UILIMIT_* (all of them).
const jobUILimitAll = 0xFF

// Job limit flags not in x/sys/windows.
const jobObjectLimitDieOnUnhandledException = 0x400

// FileIdInfo is FILE_INFO_BY_HANDLE_CLASS 18.
const fileIDInfoClass = 18

// fileIDInfo is FILE_ID_INFO.
type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

// securityCapabilities is SECURITY_CAPABILITIES.
type securityCapabilities struct {
	AppContainerSid *windows.SID
	Capabilities    *windows.SIDAndAttributes
	CapabilityCount uint32
	Reserved        uint32
}

func createRestrictedToken(existing windows.Token, flags uint32, disable []windows.SIDAndAttributes,
	restrict []windows.SIDAndAttributes) (windows.Token, error) {
	var tok windows.Token
	var pd, pr *windows.SIDAndAttributes
	if len(disable) > 0 {
		pd = &disable[0]
	}
	if len(restrict) > 0 {
		pr = &restrict[0]
	}
	r, _, err := procCreateRestrictedToken.Call(uintptr(existing), uintptr(flags),
		uintptr(len(disable)), uintptr(unsafe.Pointer(pd)), 0, 0,
		uintptr(len(restrict)), uintptr(unsafe.Pointer(pr)), uintptr(unsafe.Pointer(&tok)))
	if r == 0 {
		return 0, err
	}
	return tok, nil
}

// appContainerSID creates the profile of the named AppContainer, or finds
// the existing one, and returns its SID (freed with FreeSid). Process
// creation needs the profile: it holds the container's object directory.
func appContainerSID(name, display string) (*windows.SID, error) {
	if err := procCreateAppContainerProfile.Find(); err != nil {
		return nil, err
	}
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	d, err := windows.UTF16PtrFromString(display)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	r, _, _ := procCreateAppContainerProfile.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(d)), 0, 0, uintptr(unsafe.Pointer(&sid)))
	switch {
	case r == 0:
		return sid, nil
	case uint32(r) == 0x800700B7: // HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)
		return deriveAppContainerSID(name)
	default:
		return nil, fmt.Errorf("CreateAppContainerProfile: HRESULT 0x%08x", uint32(r))
	}
}

// deriveAppContainerSID returns the SID of the named AppContainer. The SID
// is freed with FreeSid.
func deriveAppContainerSID(name string) (*windows.SID, error) {
	if err := procDeriveAppContainerSidFromAppContainerName.Find(); err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	r, _, _ := procDeriveAppContainerSidFromAppContainerName.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&sid)))
	if r != 0 {
		return nil, windows.Errno(r & 0xFFFF)
	}
	return sid, nil
}

// createWindowStation creates a window station; an empty name lets the
// system name it after the logon session.
func createWindowStation(name string, access uint32, sa *windows.SecurityAttributes) (windows.Handle, error) {
	var p *uint16
	if name != "" {
		var err error
		if p, err = windows.UTF16PtrFromString(name); err != nil {
			return 0, err
		}
	}
	r, _, err := procCreateWindowStationW.Call(uintptr(unsafe.Pointer(p)), cwfCreateOnly, uintptr(access), uintptr(unsafe.Pointer(sa)))
	if r == 0 {
		return 0, err
	}
	return windows.Handle(r), nil
}

func closeWindowStation(h windows.Handle) { procCloseWindowStation.Call(uintptr(h)) }

func getProcessWindowStation() windows.Handle {
	r, _, _ := procGetProcessWindowStation.Call()
	return windows.Handle(r)
}

func setProcessWindowStation(h windows.Handle) error {
	r, _, err := procSetProcessWindowStation.Call(uintptr(h))
	if r == 0 {
		return err
	}
	return nil
}

// createDesktop creates a desktop on the process's window station.
func createDesktop(name string, access uint32, sa *windows.SecurityAttributes) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	r, _, err := procCreateDesktopW.Call(uintptr(unsafe.Pointer(p)), 0, 0, 0, uintptr(access), uintptr(unsafe.Pointer(sa)))
	if r == 0 {
		return 0, err
	}
	return windows.Handle(r), nil
}

func closeDesktop(h windows.Handle) { procCloseDesktop.Call(uintptr(h)) }

func isProcessInJob(p, job windows.Handle) (bool, error) {
	var in int32
	r, _, err := procIsProcessInJob.Call(uintptr(p), uintptr(job), uintptr(unsafe.Pointer(&in)))
	if r == 0 {
		return false, err
	}
	return in != 0, nil
}

// TOKEN_INFORMATION_CLASS TokenIsAppContainer and the low integrity RID.
const (
	tokenIsAppContainer     = 29
	securityMandatoryLowRID = 0x1000
)

// userObjectName returns the name of a window station or desktop.
func userObjectName(h windows.Handle) (string, error) {
	buf := make([]uint16, 256)
	var need uint32
	r, _, err := procGetUserObjectInformationW.Call(uintptr(h), 2, // UOI_NAME
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), uintptr(unsafe.Pointer(&need)))
	if r == 0 {
		return "", fmt.Errorf("GetUserObjectInformation: %w", err)
	}
	return windows.UTF16ToString(buf), nil
}
