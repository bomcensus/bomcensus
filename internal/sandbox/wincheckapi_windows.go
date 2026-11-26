// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sandbox

// COM, window and privilege calls of the check program.

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modole32    = windows.NewLazySystemDLL("ole32.dll")
	modoleaut32 = windows.NewLazySystemDLL("oleaut32.dll")

	procCoInitializeEx       = modole32.NewProc("CoInitializeEx")
	procCoUninitialize       = modole32.NewProc("CoUninitialize")
	procCoCreateInstance     = modole32.NewProc("CoCreateInstance")
	procSysAllocString       = modoleaut32.NewProc("SysAllocString")
	procSysFreeString        = modoleaut32.NewProc("SysFreeString")
	procLookupPrivilegeNameW = modadvapi32.NewProc("LookupPrivilegeNameW")
	procOpenWindowStationW   = moduser32.NewProc("OpenWindowStationW")
	procOpenInputDesktop     = moduser32.NewProc("OpenInputDesktop")
	procFindWindowW          = moduser32.NewProc("FindWindowW")
)

// call calls p, or fails when its DLL does not load: in the sandbox, DLLs
// such as ole32 and user32 may fail to initialize, and LazyProc.Call
// panics then.
func call(p *windows.LazyProc, args ...uintptr) (uintptr, error) {
	if err := p.Find(); err != nil {
		return 0, err
	}
	r, _, err := p.Call(args...)
	return r, err
}

func lookupPrivilegeName(l *windows.LUID, buf *uint16, n *uint32) error {
	if err := procLookupPrivilegeNameW.Find(); err != nil {
		return err
	}
	r, _, err := procLookupPrivilegeNameW.Call(0, uintptr(unsafe.Pointer(l)), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(n)))
	if r == 0 {
		return err
	}
	return nil
}

const (
	clsctxInprocServer = 0x1
	clsctxLocalServer  = 0x4
)

var (
	clsidWbemLocator   = windows.GUID{Data1: 0x4590F811, Data2: 0x1D3A, Data3: 0x11D0, Data4: [8]byte{0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}}
	iidIWbemLocator    = windows.GUID{Data1: 0xDC12A687, Data2: 0x737F, Data3: 0x11CF, Data4: [8]byte{0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}}
	clsidTaskScheduler = windows.GUID{Data1: 0x0F87369F, Data2: 0xA4E5, Data3: 0x4CFC, Data4: [8]byte{0xBD, 0x3E, 0x73, 0xE6, 0x15, 0x45, 0x72, 0xDD}}
	iidITaskService    = windows.GUID{Data1: 0x2FABA4C7, Data2: 0x4DA9, Data3: 0x4013, Data4: [8]byte{0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85}}
)

// comObject calls methods by vtable index.
type comObject struct{ p unsafe.Pointer }

func (o comObject) call(index int, args ...uintptr) uintptr {
	vtbl := *(*unsafe.Pointer)(o.p)
	fn := *(*uintptr)(unsafe.Add(vtbl, uintptr(index)*unsafe.Sizeof(uintptr(0))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{uintptr(o.p)}, args...)...)
	return r
}

func (o comObject) release() { o.call(2) }

func hresult(what string, r uintptr) error {
	if int32(r) < 0 {
		return fmt.Errorf("%s: HRESULT 0x%08x", what, uint32(r))
	}
	return nil
}

func coCreate(clsid, iid *windows.GUID, ctx uint32) (comObject, error) {
	var p unsafe.Pointer
	r, _ := call(procCoCreateInstance, uintptr(unsafe.Pointer(clsid)), 0, uintptr(ctx),
		uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&p)))
	if err := hresult("CoCreateInstance", r); err != nil {
		return comObject{}, err
	}
	return comObject{p}, nil
}

func withCOM(f func() error) error {
	if err := procCoInitializeEx.Find(); err != nil {
		return fmt.Errorf("ole32: %w", err)
	}
	r, _, _ := procCoInitializeEx.Call(0, windows.COINIT_MULTITHREADED)
	if err := hresult("CoInitializeEx", r); err != nil {
		return err
	}
	defer procCoUninitialize.Call()
	return f()
}

// tryWMI connects to root\cimv2, through which Win32_Process.Create would
// start a process outside the job.
func tryWMI() error {
	return withCOM(func() error {
		loc, err := coCreate(&clsidWbemLocator, &iidIWbemLocator, clsctxInprocServer)
		if err != nil {
			return err
		}
		defer loc.release()
		ns, _ := windows.UTF16PtrFromString(`ROOT\CIMV2`)
		bstr, err := call(procSysAllocString, uintptr(unsafe.Pointer(ns)))
		if bstr == 0 {
			return fmt.Errorf("SysAllocString: %w", err)
		}
		defer call(procSysFreeString, bstr)
		var svc unsafe.Pointer
		// IWbemLocator::ConnectServer
		if err := hresult("ConnectServer", loc.call(3, bstr, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&svc)))); err != nil {
			return err
		}
		comObject{svc}.release()
		return nil
	})
}

// tryTaskScheduler connects to the task scheduler, through which a
// registered task would run outside the job.
func tryTaskScheduler() error {
	return withCOM(func() error {
		ts, err := coCreate(&clsidTaskScheduler, &iidITaskService, clsctxInprocServer)
		if err != nil {
			return err
		}
		defer ts.release()
		// ITaskService::Connect takes four VARIANTs, passed by
		// reference on 64-bit Windows; empty ones mean the local
		// computer and the current user.
		var v [4][24]byte
		return hresult("ITaskService.Connect", ts.call(10, uintptr(unsafe.Pointer(&v[0])), uintptr(unsafe.Pointer(&v[1])),
			uintptr(unsafe.Pointer(&v[2])), uintptr(unsafe.Pointer(&v[3]))))
	})
}

func tryOpenWinSta0() error {
	name, _ := windows.UTF16PtrFromString("WinSta0")
	r, err := call(procOpenWindowStationW, uintptr(unsafe.Pointer(name)), 0, 0x0001) // WINSTA_ENUMDESKTOPS
	if r == 0 {
		return err
	}
	closeWindowStation(windows.Handle(r))
	return nil
}

func tryOpenInputDesktop() error {
	r, err := call(procOpenInputDesktop, 0, 0, 0x0001) // DESKTOP_READOBJECTS
	if r == 0 {
		return err
	}
	closeDesktop(windows.Handle(r))
	return nil
}

func tryFindWindow(class string) error {
	c, _ := windows.UTF16PtrFromString(class)
	r, err := call(procFindWindowW, uintptr(unsafe.Pointer(c)), 0)
	if r == 0 {
		return fmt.Errorf("not found: %v", err)
	}
	return nil
}
