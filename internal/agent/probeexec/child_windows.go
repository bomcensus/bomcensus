// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probeexec

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// defaultSocket is empty: there is no probe service on Windows.
const defaultSocket = ""

func statSocket(path string) (os.FileInfo, error) {
	if path == "" {
		return nil, os.ErrNotExist
	}
	return os.Stat(path)
}

// childEnvVars are passed from the agent's environment to the probe. A
// Windows process without SystemRoot cannot load some system DLLs.
var childEnvVars = []string{
	"SystemRoot", "SystemDrive", "windir", "ProgramData", "ProgramFiles",
	"ProgramFiles(x86)", "ProgramW6432", "TEMP", "TMP", "COMPUTERNAME",
}

func defaultEnv() []string {
	var env []string
	for _, k := range childEnvVars {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	if root := os.Getenv("SystemRoot"); root != "" {
		env = append(env, `PATH=`+root+`\System32;`+root)
	}
	return env
}

type child struct {
	cmd *exec.Cmd
	// job is the job object once the probe is in it.
	job atomic.Uintptr
}

// prepareChild starts the probe below normal priority, without a console
// and in its own process group, so that a console Ctrl+C of an interactive
// agent does not reach it first. Cancellation terminates the job, or the
// probe alone when it is not in one.
func prepareChild(cmd *exec.Cmd) *child {
	c := &child{cmd: cmd}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.BELOW_NORMAL_PRIORITY_CLASS | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW,
	}
	cmd.Cancel = func() error {
		if job := windows.Handle(c.job.Load()); job != 0 && windows.TerminateJobObject(job, 1) == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	return c
}

// started puts the started probe in a job object that kills every
// process in it when the last handle closes: on cancellation, after the
// probe exited, or when the agent dies. The probe is assigned right after
// it started; it starts no processes of its own on Windows, so nothing can
// escape in between. Failing to create the job only loses that guarantee;
// cancellation still kills the probe itself.
func (c *child) started(log *slog.Logger) func() {
	job, err := killOnCloseJob()
	if err != nil {
		log.Warn("probe job object", "error", err)
		return func() {}
	}
	if err := assignProcess(job, c.cmd.Process.Pid); err != nil {
		log.Warn("probe job object", "error", err)
		windows.CloseHandle(job)
		return func() {}
	}
	c.job.Store(uintptr(job))
	return func() {
		c.job.Store(0)
		windows.CloseHandle(job)
	}
}

func killOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func assignProcess(job windows.Handle, pid int) error {
	if pid <= 0 {
		return errors.New("no process id")
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(job, h)
}
