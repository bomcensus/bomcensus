// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sandbox

// Version commands on Windows (SECURITY.md 6.6).
//
// The target is a third-party executable that does not cooperate, so every
// restriction is in place when the process is created; there is no initial
// token that is lowered later (as Chromium's targets do). Run applies:
//
//   - the file: a native console PE (NativeConsolePE), opened without
//     write or delete sharing from the check until the process exits, and
//     the image of the created process compared with it by file ID
//   - a restricted token of the probe's token: every privilege but
//     SeChangeNotifyPrivilege removed, the user and all groups but
//     Everyone, Users, Administrators and Authenticated Users deny-only,
//     restricting SIDs Everyone, Users, Authenticated Users and RESTRICTED
//     (access needs a grant to one of them as well), low integrity
//   - an AppContainer without capabilities: no network, loopback included,
//     and access only where ALL APPLICATION PACKAGES (or, as a less
//     privileged AppContainer tried first, ALL RESTRICTED APPLICATION
//     PACKAGES) is granted; COM and RPC services refuse it
//   - a job object assigned at creation: one process, killed with the job,
//     no breakaway, process memory and CPU time limits, every UI limit
//   - the child process policy (no child processes) and the desktop app
//     breakaway policy
//   - mitigations: strict handle checks, extension points, font loading,
//     remote and low-label images disabled, System32 images preferred,
//     ASLR forced, heap termination; win32k lockdown and dynamic code
//     prohibition on request (they break programs that use user32 or a JIT)
//   - a private window station and desktop, so the command sees no window,
//     clipboard or input of a user. A user account can create a window
//     station only when its logon session has none yet; otherwise the
//     command gets a private desktop on the probe's window station, which
//     its token cannot connect to: programs that load user32 do not start
//     then (Result.WindowStation tells which). Keeping the logon SID would
//     let them, and would also open the user's input desktop to them.
//   - only three handles inherited (NUL stdin, stdout and stderr pipes),
//     an environment of the given variables, SystemRoot and LOCALAPPDATA,
//     TEMP and TMP (the AppContainer's folder, set by Windows), cwd System32,
//     no console, the error mode of the probe (no hard error dialogs)
//   - a timeout after which the job is terminated, and output truncated
//     per stream

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Command is one version command.
type Command struct {
	// Path is the absolute path of the executable.
	Path string
	// Args follow the program name on the command line.
	Args []string
	// Env holds NAME=value entries; nothing else is inherited but
	// SystemRoot, and the AppContainer's folder as LOCALAPPDATA, TEMP and
	// TMP.
	Env []string

	Timeout     time.Duration // default 10 s
	CPUTime     time.Duration // user time, default 10 s
	MemoryMB    int           // committed memory, default 2048
	OutputLimit int           // bytes per stream, default 64 KiB

	// Win32kLockdown disables win32k system calls; ProhibitDynamicCode
	// forbids executable memory that is not an image. Both are off by
	// default because programs that load user32 or JIT-compile fail.
	Win32kLockdown      bool
	ProhibitDynamicCode bool
}

// Result is the outcome of a command that ran.
type Result struct {
	Stdout, Stderr []byte
	Truncated      bool
	ExitCode       uint32
	TimedOut       bool
	// FileID identifies the executed file (volume serial and file ID).
	FileID string
	// Container is "lpac" or "appcontainer": the AppContainer kind the
	// command ran in.
	Container string
	// WindowStation is the kind of window station of its desktop
	// (WinstaPrivate, WinstaSession or WinstaCurrent).
	WindowStation string
}

// Defaults of Command.
const (
	DefaultTimeout     = 10 * time.Second
	DefaultCPUTime     = 10 * time.Second
	DefaultMemoryMB    = 2048
	DefaultOutputLimit = 64 << 10
)

// AppContainerName is the AppContainer of version commands. Its profile is
// created on first use (per account) and kept.
const AppContainerName = "bomcensus.version-command"

// Errors of Run before the command started.
var (
	ErrFileBusy  = errors.New("the file is open for writing")
	ErrImageDiff = errors.New("the process image is not the checked file")
)

// containerOrder: LPAC first, then a regular AppContainer (tests change
// it to check each alone).
var containerOrder = []bool{true, false}

// notStarted reports a command that printed nothing on stdout and ended
// with an NTSTATUS error or warning (DLL not found or not initialized,
// access denied, a crash): in LPAC that is taken as a program that cannot
// run there (node fails in WSAStartup), and it is run again in a regular
// AppContainer.
func notStarted(r *Result) bool {
	return !r.TimedOut && r.ExitCode >= 0x80000000 && len(r.Stdout) == 0
}

// Run executes the command in the sandbox. It returns an error when the
// command could not be started; a command that started and failed is a
// Result with its exit code.
func Run(ctx context.Context, c Command) (*Result, error) {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.CPUTime <= 0 {
		c.CPUTime = DefaultCPUTime
	}
	if c.MemoryMB <= 0 {
		c.MemoryMB = DefaultMemoryMB
	}
	if c.OutputLimit <= 0 {
		c.OutputLimit = DefaultOutputLimit
	}
	if !filepath.IsAbs(c.Path) {
		return nil, fmt.Errorf("%s: not an absolute path", c.Path)
	}
	f, err := openLocked(c.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := NativeConsolePE(f, runtime.GOARCH); err != nil {
		return nil, err
	}
	id, err := fileID(windows.Handle(f.Fd()))
	if err != nil {
		return nil, err
	}

	desk, err := newDesktop()
	if err != nil {
		return nil, fmt.Errorf("desktop: %w", err)
	}
	defer desk.close()
	tok, err := commandToken()
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	defer tok.Close()
	sid, err := commandContainer()
	if err != nil {
		return nil, fmt.Errorf("appcontainer: %w", err)
	}

	var lastErr error
	for _, lpac := range containerOrder {
		res, err := runOnce(ctx, c, id, tok, sid, desk, lpac)
		if err != nil {
			lastErr = err
			if lpac && errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				continue
			}
			return nil, err
		}
		if lpac && notStarted(res) {
			lastErr = fmt.Errorf("exit 0x%08x", res.ExitCode)
			continue
		}
		return res, nil
	}
	return nil, fmt.Errorf("not started in an AppContainer: %w", lastErr)
}

var (
	containerMu  sync.Mutex
	containerSID *windows.SID
)

// commandContainer returns the SID of the AppContainer of commands,
// creating its profile on the first call of the process. The SID is kept:
// CreateAppContainerProfile takes milliseconds and fails when called
// concurrently (E_UNEXPECTED, ERROR_KEY_DELETED).
func commandContainer() (*windows.SID, error) {
	containerMu.Lock()
	defer containerMu.Unlock()
	if containerSID == nil {
		sid, err := appContainerSID(AppContainerName, "bomcensus version command")
		if err != nil {
			return nil, err
		}
		containerSID = sid
	}
	return containerSID, nil
}

// openLocked opens path for reading, sharing only reading, without
// following a final symbolic link or junction.
func openLocked(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, fmt.Errorf("%s: %w", path, ErrFileBusy)
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	return os.NewFile(uintptr(h), path), nil
}

func fileID(h windows.Handle) (string, error) {
	var info fileIDInfo
	if err := windows.GetFileInformationByHandleEx(h, fileIDInfoClass, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return "", fmt.Errorf("file id: %w", err)
	}
	return fmt.Sprintf("%016x-%s", info.VolumeSerialNumber, hex.EncodeToString(info.FileID[:])), nil
}

// imageID returns the file ID of the image of process p.
func imageID(p windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(p, 0, &buf[0], &n); err != nil {
		return "", err
	}
	h, err := windows.CreateFile(&buf[0], windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	return fileID(h)
}

var (
	sidEveryone      = mustSID("S-1-1-0")
	sidUsers         = mustSID("S-1-5-32-545")
	sidAdmins        = mustSID("S-1-5-32-544")
	sidAuthenticated = mustSID("S-1-5-11")
	sidRestricted    = mustSID("S-1-5-12")
	sidLowLabel      = mustSID("S-1-16-4096")
)

func mustSID(s string) *windows.SID {
	sid, err := windows.StringToSid(s)
	if err != nil {
		panic(err)
	}
	return sid
}

// commandToken returns the restricted primary token of commands.
func commandToken() (windows.Token, error) {
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT, &self); err != nil {
		return 0, err
	}
	defer self.Close()
	user, err := self.GetTokenUser()
	if err != nil {
		return 0, err
	}
	groups, err := self.GetTokenGroups()
	if err != nil {
		return 0, err
	}
	keep := []*windows.SID{sidEveryone, sidUsers, sidAdmins, sidAuthenticated}
	disable := []windows.SIDAndAttributes{{Sid: user.User.Sid}}
	restrict := []windows.SIDAndAttributes{{Sid: sidEveryone}, {Sid: sidUsers}, {Sid: sidAuthenticated}, {Sid: sidRestricted}}
	for _, g := range groups.AllGroups() {
		if g.Attributes&windows.SE_GROUP_INTEGRITY != 0 {
			continue
		}
		kept := false
		for _, k := range keep {
			if g.Sid.Equals(k) {
				kept = true
			}
		}
		if !kept {
			disable = append(disable, windows.SIDAndAttributes{Sid: g.Sid})
		}
	}
	tok, err := createRestrictedToken(self, disableMaxPrivilege, disable, restrict)
	if err != nil {
		return 0, fmt.Errorf("CreateRestrictedToken: %w", err)
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: sidLowLabel, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(tok, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)),
		label.Size()); err != nil {
		tok.Close()
		return 0, fmt.Errorf("integrity level: %w", err)
	}
	return tok, nil
}

// desktop is a private desktop on the private window station.
type desktop struct {
	desk windows.Handle
	name string // winsta\desktop
}

// Rights of commands on the window station and their desktop: everything
// needed to initialize user32 and create windows there. The objects are
// the probe's own, labeled low so that the low integrity commands can use
// them.
const (
	winstaRights = 0x0002037F // WINSTA_ALL_ACCESS | READ_CONTROL
	deskRights   = 0x000200FF // DESKTOP_ALL_ACCESS without SWITCHDESKTOP | READ_CONTROL
)

var (
	winstaOnce sync.Once
	winsta     windows.Handle
	winstaName string
	winstaKind string
	winstaErr  error
	winstaMu   sync.Mutex
)

// Kinds of window station of commands (Result.WindowStation).
const (
	WinstaPrivate = "private" // created for the probe
	WinstaSession = "session" // the logon session's, created by the probe
	WinstaCurrent = "current" // the probe's own; the desktop is private
)

// objectSA is the security of the window station and the desktops.
func objectSA(rights uint32) (*windows.SecurityAttributes, error) {
	me, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	r := fmt.Sprintf("0x%x", rights)
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;" + me + ")" +
		"(A;;" + r + ";;;WD)(A;;" + r + ";;;AC)(A;;" + r + ";;;S-1-15-2-2)(A;;" + r + ";;;RC)S:(ML;;NW;;;LW)")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

// privateWinsta creates the window station of commands once per process.
// A named one needs more than a user account has; the unnamed one is
// named after the logon session and can exist once per session. When
// neither can be created, commands get a private desktop on the probe's
// window station: the job's UI limits keep them from its clipboard and
// global atoms, and the desktop from its windows.
func privateWinsta() (windows.Handle, string, error) {
	winstaOnce.Do(func() {
		sa, err := objectSA(winstaRights)
		if err != nil {
			winstaErr = err
			return
		}
		var nb [8]byte
		if _, err := rand.Read(nb[:]); err != nil {
			winstaErr = err
			return
		}
		name := "bomcensus-" + hex.EncodeToString(nb[:])
		winstaKind = WinstaPrivate
		h, err := createWindowStation(name, windows.MAXIMUM_ALLOWED, sa)
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			winstaKind = WinstaSession
			h, err = createWindowStation("", windows.MAXIMUM_ALLOWED, sa)
		}
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			winstaKind, h, err = WinstaCurrent, getProcessWindowStation(), nil
		}
		if err != nil {
			winstaErr = fmt.Errorf("CreateWindowStation: %w", err)
			return
		}
		if name, err = userObjectName(h); err != nil {
			if winstaKind != WinstaCurrent {
				closeWindowStation(h)
			}
			winstaErr = err
			return
		}
		winsta, winstaName = h, name
	})
	return winsta, winstaName, winstaErr
}

func newDesktop() (*desktop, error) {
	ws, wsName, err := privateWinsta()
	if err != nil {
		return nil, err
	}
	sa, err := objectSA(deskRights)
	if err != nil {
		return nil, err
	}
	var nb [8]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return nil, err
	}
	name := "bomcensus-" + hex.EncodeToString(nb[:])
	// CreateDesktop creates the desktop on the process's window station.
	winstaMu.Lock()
	defer winstaMu.Unlock()
	old := getProcessWindowStation()
	if err := setProcessWindowStation(ws); err != nil {
		return nil, fmt.Errorf("SetProcessWindowStation: %w", err)
	}
	desk, derr := createDesktop(name, windows.MAXIMUM_ALLOWED, sa)
	if err := setProcessWindowStation(old); err != nil {
		// Nothing else in the probe uses a window station.
		return nil, fmt.Errorf("SetProcessWindowStation back: %w", err)
	}
	if derr != nil {
		return nil, fmt.Errorf("CreateDesktop: %w", derr)
	}
	return &desktop{desk: desk, name: wsName + `\` + name}, nil
}

func (d *desktop) close() { closeDesktop(d.desk) }

func currentUserSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// newJob returns the job of one command.
func newJob(c Command) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var lim windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	lim.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
		windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | jobObjectLimitDieOnUnhandledException |
		windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY | windows.JOB_OBJECT_LIMIT_PROCESS_TIME
	lim.BasicLimitInformation.ActiveProcessLimit = 1
	lim.BasicLimitInformation.PerProcessUserTimeLimit = c.CPUTime.Nanoseconds() / 100
	lim.ProcessMemoryLimit = uintptr(c.MemoryMB) << 20
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&lim)), uint32(unsafe.Sizeof(lim))); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("job limits: %w", err)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: jobUILimitAll}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("job UI limits: %w", err)
	}
	return job, nil
}

// envBlock is the environment block of the command, sorted as Windows
// expects.
func envBlock(env []string) (*uint16, error) {
	vars := map[string]string{}
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok || k == "" || strings.ContainsRune(e, 0) {
			return nil, fmt.Errorf("bad environment entry %q", e)
		}
		vars[strings.ToUpper(k)] = k + "=" + v
	}
	if _, ok := vars["SYSTEMROOT"]; !ok {
		vars["SYSTEMROOT"] = "SystemRoot=" + systemRoot()
	}
	// Process creation in an AppContainer derives the container's
	// folder from LOCALAPPDATA and sets LOCALAPPDATA, TEMP and TMP of the
	// command to it.
	if _, ok := vars["LOCALAPPDATA"]; !ok {
		d, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
		if err != nil {
			return nil, fmt.Errorf("LocalAppData: %w", err)
		}
		vars["LOCALAPPDATA"] = "LOCALAPPDATA=" + d
	}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b []uint16
	for _, k := range keys {
		u, err := windows.UTF16FromString(vars[k])
		if err != nil {
			return nil, err
		}
		b = append(b, u...)
	}
	b = append(b, 0)
	return &b[0], nil
}

func systemRoot() string {
	d, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return `C:\Windows`
	}
	return d
}

func runOnce(ctx context.Context, c Command, id string, tok windows.Token, sid *windows.SID,
	desk *desktop, lpac bool) (*Result, error) {
	env, err := envBlock(c.Env)
	if err != nil {
		return nil, err
	}
	app, err := windows.UTF16PtrFromString(c.Path)
	if err != nil {
		return nil, err
	}
	cmdline, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{c.Path}, c.Args...)))
	if err != nil {
		return nil, err
	}
	sys32, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	cwd, err := windows.UTF16PtrFromString(sys32)
	if err != nil {
		return nil, err
	}
	deskName, err := windows.UTF16PtrFromString(desk.name)
	if err != nil {
		return nil, err
	}

	job, err := newJob(c)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(job)

	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer outR.Close()
	errR, errW, err := os.Pipe()
	if err != nil {
		outW.Close()
		return nil, err
	}
	defer errR.Close()
	nul, err := os.Open(os.DevNull)
	if err != nil {
		outW.Close()
		errW.Close()
		return nil, err
	}
	handles := []windows.Handle{windows.Handle(nul.Fd()), windows.Handle(outW.Fd()), windows.Handle(errW.Fd())}
	jobs := []windows.Handle{job}
	caps := securityCapabilities{AppContainerSid: sid}
	childPolicy := uint32(processCreationChildProcessRestricted)
	aapPolicy := uint32(processCreationAllApplicationPackagesOptOut)
	desktopPolicy := uint32(processCreationDesktopAppBreakawayDisableProcessTree)
	mitigations := [2]uint64{mitigationForceRelocateImagesAlwaysOn | mitigationHeapTerminateAlwaysOn |
		mitigationBottomUpASLRAlwaysOn | mitigationHighEntropyASLRAlwaysOn | mitigationStrictHandleChecksAlwaysOn |
		mitigationExtensionPointDisableOn | mitigationFontDisableOn | mitigationImageLoadNoRemoteOn |
		mitigationImageLoadNoLowLabelOn | mitigationImageLoadPreferSystem32On}
	if c.Win32kLockdown {
		mitigations[0] |= mitigationWin32kSystemCallDisableOn
	}
	if c.ProhibitDynamicCode {
		mitigations[0] |= mitigationProhibitDynamicCodeOn
	}
	n := uint32(7)
	if lpac {
		n++
	}
	attrs, err := windows.NewProcThreadAttributeList(n)
	if err != nil {
		nul.Close()
		outW.Close()
		errW.Close()
		return nil, err
	}
	defer attrs.Delete()
	set := func(attr uintptr, p unsafe.Pointer, size uintptr) {
		if err == nil {
			err = attrs.Update(attr, p, size)
		}
	}
	set(procThreadAttributeHandleList, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0]))
	set(procThreadAttributeJobList, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs[0]))
	set(procThreadAttributeSecurityCapabilities, unsafe.Pointer(&caps), unsafe.Sizeof(caps))
	set(procThreadAttributeChildProcessPolicy, unsafe.Pointer(&childPolicy), unsafe.Sizeof(childPolicy))
	set(procThreadAttributeDesktopAppPolicy, unsafe.Pointer(&desktopPolicy), unsafe.Sizeof(desktopPolicy))
	set(procThreadAttributeMitigationPolicy, unsafe.Pointer(&mitigations), unsafe.Sizeof(mitigations))
	if lpac {
		set(procThreadAttributeAllApplicationPackagesPolicy, unsafe.Pointer(&aapPolicy), unsafe.Sizeof(aapPolicy))
	}
	if err != nil {
		nul.Close()
		outW.Close()
		errW.Close()
		return nil, fmt.Errorf("process attributes: %w", err)
	}

	si := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdInput, si.StdOutput, si.StdErr = handles[0], handles[1], handles[2]
	si.Desktop = deskName
	var pi windows.ProcessInformation
	flags := uint32(windows.CREATE_SUSPENDED | windows.EXTENDED_STARTUPINFO_PRESENT |
		windows.CREATE_UNICODE_ENVIRONMENT | windows.DETACHED_PROCESS)

	// The three handles are inheritable only while the process is
	// created; ForkLock keeps other process creations of this program
	// from inheriting them meanwhile.
	syscall.ForkLock.Lock()
	for _, h := range handles {
		if err == nil {
			err = windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT)
		}
	}
	if err == nil {
		err = windows.CreateProcessAsUser(tok, app, cmdline, nil, nil, true, flags, env, cwd, &si.StartupInfo, &pi)
	}
	for _, h := range handles {
		windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, 0)
	}
	syscall.ForkLock.Unlock()
	nul.Close()
	outW.Close()
	errW.Close()
	runtime.KeepAlive(&caps)
	runtime.KeepAlive(handles)
	runtime.KeepAlive(jobs)
	runtime.KeepAlive(&mitigations)
	if err != nil {
		return nil, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	kill := func() { windows.TerminateJobObject(job, 1) }
	if in, err := isProcessInJob(pi.Process, job); err != nil || !in {
		kill()
		return nil, fmt.Errorf("process not in its job: %v", err)
	}
	if got, err := imageID(pi.Process); err != nil || got != id {
		kill()
		if err != nil {
			return nil, fmt.Errorf("process image: %w", err)
		}
		return nil, ErrImageDiff
	}

	res := &Result{FileID: id, Container: "appcontainer", WindowStation: winstaKind}
	if lpac {
		res.Container = "lpac"
	}
	var wg sync.WaitGroup
	var outTrunc, errTrunc bool
	wg.Add(2)
	go func() { defer wg.Done(); res.Stdout, outTrunc = readLimited(outR, c.OutputLimit) }()
	go func() { defer wg.Done(); res.Stderr, errTrunc = readLimited(errR, c.OutputLimit) }()

	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		kill()
		wg.Wait()
		return nil, fmt.Errorf("ResumeThread: %w", err)
	}
	deadline := time.Now().Add(c.Timeout)
	for {
		ev, err := windows.WaitForSingleObject(pi.Process, 50)
		if err != nil {
			kill()
			wg.Wait()
			return nil, err
		}
		if ev == windows.WAIT_OBJECT_0 {
			break
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			res.TimedOut = ctx.Err() == nil
			kill()
			windows.WaitForSingleObject(pi.Process, windows.INFINITE)
			break
		}
	}
	// Nothing of the command outlives it.
	kill()
	wg.Wait()
	if err := windows.GetExitCodeProcess(pi.Process, &res.ExitCode); err != nil {
		return nil, err
	}
	res.Truncated = outTrunc || errTrunc
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	return res, nil
}

// readLimited reads r to the end, keeping at most limit bytes.
func readLimited(r io.Reader, limit int) ([]byte, bool) {
	buf := make([]byte, 0, min(limit, 4096))
	tmp := make([]byte, 4096)
	total := 0
	for {
		n, err := r.Read(tmp)
		total += n
		if room := limit - len(buf); n > 0 && room > 0 {
			buf = append(buf, tmp[:min(n, room)]...)
		}
		if err != nil {
			return buf, total > limit
		}
	}
}
