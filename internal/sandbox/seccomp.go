// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux && (amd64 || arm64)

package sandbox

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BPF opcodes, seccomp_data offsets and return values.
const (
	bpfLdAbsW     = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	bpfJeqK       = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	bpfJgeK       = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
	bpfJsetK      = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
	bpfJa         = unix.BPF_JMP | unix.BPF_JA
	bpfAndK       = unix.BPF_ALU | unix.BPF_AND | unix.BPF_K
	bpfRetK       = unix.BPF_RET | unix.BPF_K
	offNr         = 0
	offArch       = 4
	offArgsLow    = 16 // args[i] low 32 bits on little-endian: 16 + 8*i
	x32SyscallBit = 0x40000000

	// RetAllow lets the call through.
	RetAllow = unix.SECCOMP_RET_ALLOW
	// RetKill kills the whole process.
	RetKill = unix.SECCOMP_RET_KILL_PROCESS
)

// Supported reports whether filters can be built for this architecture.
const Supported = true

// Errno is the filter return value that fails a call with e.
func Errno(e unix.Errno) uint32 { return unix.SECCOMP_RET_ERRNO | uint32(e)&unix.SECCOMP_RET_DATA }

// Rule denies one system call with Ret. Without conditions the call is
// always denied; otherwise it is denied when any condition holds.
type Rule struct {
	Nr    uintptr
	Ret   uint32
	Conds []Cond
}

// CondOp is how a condition tests an argument.
type CondOp int

// Condition operators. Only the low 32 bits of an argument are compared,
// which covers int, unsigned int and the flag words of the calls used here.
const (
	// AnyBits holds when the argument has any bit of K set.
	AnyBits CondOp = iota + 1
	// MissingBits holds when the argument lacks any bit of K.
	MissingBits
	// In holds when the argument equals one of Values.
	In
	// NotIn holds when the argument equals none of Values.
	NotIn
)

// Cond is a test on argument Arg (0 to 5).
type Cond struct {
	Arg    int
	Op     CondOp
	K      uint32
	Values []uint32
}

// Deny returns unconditional rules for nrs.
func Deny(ret uint32, nrs ...uintptr) []Rule {
	out := make([]Rule, 0, len(nrs))
	for _, nr := range nrs {
		out = append(out, Rule{Nr: nr, Ret: ret})
	}
	return out
}

// Jump targets inside the block of one rule.
const (
	toFall = iota // the following instruction
	toDeny        // the deny return of the rule
	toNext        // the first instruction of the next condition
)

type symInsn struct {
	in     unix.SockFilter
	jt, jf int // targets of a conditional jump
	ja     bool
}

// condBlock assembles the conditions of r. The block returns on every
// path: allow when no condition holds, r.Ret otherwise.
func condBlock(r Rule) ([]unix.SockFilter, error) {
	var code []symInsn
	var starts []int
	emit := func(in unix.SockFilter, jt, jf int) { code = append(code, symInsn{in: in, jt: jt, jf: jf}) }
	for _, c := range r.Conds {
		if c.Arg < 0 || c.Arg > 5 {
			return nil, fmt.Errorf("seccomp rule %d: argument %d", r.Nr, c.Arg)
		}
		starts = append(starts, len(code))
		emit(unix.SockFilter{Code: bpfLdAbsW, K: uint32(offArgsLow + 8*c.Arg)}, toFall, toFall)
		switch c.Op {
		case AnyBits:
			emit(unix.SockFilter{Code: bpfJsetK, K: c.K}, toDeny, toFall)
		case MissingBits:
			emit(unix.SockFilter{Code: bpfAndK, K: c.K}, toFall, toFall)
			emit(unix.SockFilter{Code: bpfJeqK, K: c.K}, toFall, toDeny)
		case In:
			for _, v := range c.Values {
				emit(unix.SockFilter{Code: bpfJeqK, K: v}, toDeny, toFall)
			}
		case NotIn:
			for _, v := range c.Values {
				emit(unix.SockFilter{Code: bpfJeqK, K: v}, toNext, toFall)
			}
			code = append(code, symInsn{in: unix.SockFilter{Code: bpfJa}, jt: toDeny, ja: true})
		default:
			return nil, fmt.Errorf("seccomp rule %d: unknown condition", r.Nr)
		}
	}
	allow := len(code)
	starts = append(starts, allow)
	code = append(code,
		symInsn{in: unix.SockFilter{Code: bpfRetK, K: RetAllow}},
		symInsn{in: unix.SockFilter{Code: bpfRetK, K: r.Ret}})
	deny := allow + 1

	out := make([]unix.SockFilter, len(code))
	cond := 0
	for i, s := range code {
		for cond+1 < len(starts) && i >= starts[cond+1] {
			cond++
		}
		target := func(t int) (int, error) {
			var to int
			switch t {
			case toFall:
				to = i + 1
			case toDeny:
				to = deny
			default:
				to = starts[cond+1]
			}
			off := to - (i + 1)
			if off < 0 || off > 255 {
				return 0, fmt.Errorf("seccomp rule %d: jump out of range", r.Nr)
			}
			return off, nil
		}
		in := s.in
		switch {
		case s.ja:
			off, err := target(s.jt)
			if err != nil {
				return nil, err
			}
			in.K = uint32(off)
		case in.Code&0x07 == unix.BPF_JMP:
			jt, err := target(s.jt)
			if err != nil {
				return nil, err
			}
			jf, err := target(s.jf)
			if err != nil {
				return nil, err
			}
			in.Jt, in.Jf = uint8(jt), uint8(jf)
		}
		out[i] = in
	}
	return out, nil
}

// Build assembles the filter program for rules. Calls of a foreign
// architecture (and x32 calls on amd64) kill the process; calls without a
// rule are allowed. A system call may have only one rule.
func Build(rules []Rule) ([]unix.SockFilter, error) {
	stmt := func(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
	jump := func(code uint16, k uint32, jt, jf int) unix.SockFilter {
		return unix.SockFilter{Code: code, K: k, Jt: uint8(jt), Jf: uint8(jf)}
	}
	prog := []unix.SockFilter{
		stmt(bpfLdAbsW, offArch),
		jump(bpfJeqK, AuditArch, 1, 0),
		stmt(bpfRetK, RetKill),
		stmt(bpfLdAbsW, offNr),
	}
	if checkX32 {
		prog = append(prog, jump(bpfJgeK, x32SyscallBit, 0, 1), stmt(bpfRetK, RetKill))
	}
	seen := map[uintptr]bool{}
	for _, r := range rules {
		if seen[r.Nr] {
			return nil, fmt.Errorf("seccomp: two rules for system call %d", r.Nr)
		}
		seen[r.Nr] = true
		if len(r.Conds) == 0 {
			prog = append(prog, jump(bpfJeqK, uint32(r.Nr), 0, 1), stmt(bpfRetK, r.Ret))
			continue
		}
		block, err := condBlock(r)
		if err != nil {
			return nil, err
		}
		if len(block) > 255 {
			return nil, fmt.Errorf("seccomp rule %d: block too long", r.Nr)
		}
		// The block returns on every path, so the system call number need
		// not be reloaded after it.
		prog = append(prog, jump(bpfJeqK, uint32(r.Nr), 0, len(block)))
		prog = append(prog, block...)
	}
	prog = append(prog, stmt(bpfRetK, RetAllow))
	if len(prog) > unix.BPF_MAXINSNS {
		return nil, fmt.Errorf("seccomp filter too long: %d instructions", len(prog))
	}
	return prog, nil
}

// Install loads prog. With allThreads it applies to every thread of the
// process (SECCOMP_FILTER_FLAG_TSYNC), otherwise to the calling thread,
// which keeps it across execve. The caller must have set no_new_privs.
func Install(prog []unix.SockFilter, allThreads bool) error {
	if len(prog) == 0 {
		return errors.New("seccomp: empty filter")
	}
	var flags uintptr
	if allThreads {
		flags = unix.SECCOMP_FILTER_FLAG_TSYNC
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	r, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(&fprog)))
	switch {
	case e != 0:
		return fmt.Errorf("seccomp: %w", e)
	case r != 0:
		return fmt.Errorf("seccomp: thread %d could not be synchronized", r)
	}
	return nil
}
