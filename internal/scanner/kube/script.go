// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

// collectScript runs inside the target container as `sh -c collectScript
// bomcensus NONCE MEMLIMIT MAXPROCS DIR...`. It is plain POSIX sh (BusyBox
// ash, dash, bash).
//
// Protocol. Status lines go to stderr as "@@BOMCENSUS-<NONCE> <TOKEN> [ARG]":
//
//	START <uname -m>   the shell runs
//	NOTOOL <name>      a required tool is missing (exit 4)
//	NODIR              no candidate directory is writable and executable (exit 3)
//	WANT <path>        the private file exists; send the probe
//	SHORT              the probe was not received completely (exit 5)
//	READY              the probe is in place; send the request
//	PID <pid>          the probe runs with this pid
//	EXIT <rc>          the probe exited with rc
//
// Stdin carries, in order and each only after the matching status line:
// after WANT a decimal byte count and a newline followed by exactly that many
// probe bytes, after READY the request JSON up to end of input. The scanner
// never sends request bytes before READY, so a reader that buffers (BusyBox
// head reads through stdio) cannot consume them while the probe is copied.
// Stdout is only the probe's stdout.
//
// The probe runs in the background so that the traps can act while it runs.
// A shell without job control gives background commands /dev/null as stdin
// before applying their redirections (dash does), so stdin is passed through
// descriptor 3.
//
// The file is created with umask 077 under a name containing the nonce,
// with noclobber so that an existing file is never reused, and removed by
// the EXIT trap; HUP, INT, PIPE and TERM exit through that trap and also
// kill the probe. A directory qualifies when an empty file created there
// can be executed (an empty file runs as an empty shell script unless the
// mount is noexec). Leftovers older than an hour from interrupted runs are
// removed from the candidate directories when find is available.
const collectScript = `n0=$1 mem=$2 procs=$3
shift 3
t="@@BOMCENSUS-$n0"
f=
pid=
say() { printf '%s %s\n' "$t" "$*" >&2; }
cleanup() {
	if [ -n "$pid" ]; then kill "$pid" 2>/dev/null; fi
	if [ -n "$f" ]; then rm -f "$f"; fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 141' PIPE
trap 'exit 143' TERM
umask 077
say START "$(uname -m 2>/dev/null)"
for c in rm chmod; do
	command -v "$c" >/dev/null 2>&1 || { say NOTOOL "$c"; exit 4; }
done
if head -c 1 </dev/null >/dev/null 2>&1; then
	rd=head
elif command -v dd >/dev/null 2>&1 && command -v wc >/dev/null 2>&1; then
	rd=dd
else
	say NOTOOL head
	exit 4
fi
sweep=
if command -v find >/dev/null 2>&1; then sweep=1; fi
for d in "$@"; do
	[ -d "$d" ] && [ -w "$d" ] && [ -x "$d" ] || continue
	if [ -n "$sweep" ]; then
		find "$d" -maxdepth 1 -type f -name '.bomcensus-*' -mmin +60 -exec rm -f {} \; 2>/dev/null
	fi
	c="${d%/}/.bomcensus-$n0"
	(set -C; : >"$c") 2>/dev/null || continue
	f=$c
	if chmod 700 "$f" 2>/dev/null && "$f" </dev/null >/dev/null 2>&1; then
		break
	fi
	rm -f "$f"
	f=
done
if [ -z "$f" ]; then
	say NODIR
	exit 3
fi
say WANT "$f"
n=
IFS= read -r n
case $n in
''|*[!0-9]*) say SHORT; exit 5 ;;
esac
if [ "$rd" = head ]; then
	head -c "$n" >"$f"
else
	got=0
	while [ "$got" -lt "$n" ]; do
		dd bs=65536 count=1 2>/dev/null >>"$f" || break
		now=$(( $(wc -c <"$f") ))
		[ "$now" -gt "$got" ] || break
		got=$now
	done
fi
if command -v wc >/dev/null 2>&1; then
	[ "$(( $(wc -c <"$f") ))" -eq "$n" ] || { say SHORT; exit 5; }
fi
say READY
exec 3<&0
GOMEMLIMIT=$mem GOMAXPROCS=$procs "$f" collect 0<&3 3<&- &
pid=$!
exec 3<&-
say PID "$pid"
wait "$pid"
rc=$?
pid=
say EXIT "$rc"
exit "$rc"
`

// cleanupScript runs as `sh -c cleanupScript bomcensus PID PATH` after a
// session ended without the script's own cleanup (timeout, lost
// connection). It kills the probe only if the pid still runs that file.
const cleanupScript = `p=$1 f=$2
if [ -n "$p" ] && command -v readlink >/dev/null 2>&1; then
	case $(readlink "/proc/$p/exe" 2>/dev/null) in
	"$f"|"$f (deleted)") kill "$p" 2>/dev/null ;;
	esac
fi
rm -f "$f"
`

// Status tokens written by collectScript.
const (
	tokStart  = "START"
	tokNoTool = "NOTOOL"
	tokNoDir  = "NODIR"
	tokWant   = "WANT"
	tokShort  = "SHORT"
	tokReady  = "READY"
	tokPID    = "PID"
	tokExit   = "EXIT"
)

// probeFileName is the file created in the chosen directory.
func probeFileName(nonce string) string { return ".bomcensus-" + nonce }
