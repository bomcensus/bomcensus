# Package file integrity

bomcensus compares the files of installed OS packages with the digests their
package database records, like `dpkg --verify` and `rpm -Va`, and shows files
that differ with the expected and the actual digest. It runs on Linux hosts
with an agent (including the Kubernetes node agent) and on SSH scan targets.

## What is checked

The probe reads the package databases itself; it does not run `dpkg` or `rpm`.

| Database | Expected digest | Left out |
|---|---|---|
| dpkg | `/var/lib/dpkg/info/<pkg>.md5sums` (MD5) | conffiles (`Conffiles:` in the status file); files no longer in the package's `.list` (taken over by another package). Diverted files are checked at the diversion target. |
| rpm | `FILEDIGESTS` in the algorithm of `FILEDIGESTALGO` (SHA-256 on current systems) | `%config`, `%ghost`, files whose verify flags exclude the digest, files not installed (`--excludedocs`, other architecture) |
| apk | `Z:` checksum (SHA-1) | `/etc`, symlinks |

Only packages in a final state are checked (dpkg `installed` and
`triggers-*`). Files larger than 1 GiB, `/proc`, `/sys`, `/dev`, `/run` and the
policy's exclude paths are left out. A file that is replaced by a symlink is
read through the link.

A file is reported as `modified` (with the actual digest in the database's
algorithm, and its SHA-256 when that algorithm is not SHA-256) or `missing`.
Files the probe cannot read are counted and lower the pass's coverage to
partial; without sudo, an SSH target reports most files under `/usr` anyway.

## When it runs

The policy (**Settings › File integrity**) sets a daily window in the host's
local time (default 02:00–05:00), the interval between passes (default one
day), the read rate per host (default 20 MB/s), the full rehash interval
(default 7 days) and exclude paths. Passes are on by default for agents and
for SSH targets; each agent and each scan target can follow the default or
turn passes on or off.

- The start is spread over the first half of the window per host, so that
  hosts on shared storage do not start together.
- A pass may need several chunks. A chunk that reaches the end of the window
  stops, and the next window continues where it stopped.
- Reads are paced to the read rate, pause while CPU or I/O pressure
  (`/proc/pressure`) is high, and are dropped from the page cache afterwards.
  The probe runs at nice 19 and in the idle I/O class.
- A chunk does not start while dpkg or rpm holds its lock; one that sees a
  lock at its end is repeated. Findings of packages whose version changed
  during the chunk are dropped.
- Agents run passes apart from collections, which continue meanwhile. SSH
  targets run chunks of at most 25 minutes, at most two at a time per scanner;
  a lost connection costs one chunk.

### Cache

Agents keep a cache of digests of files that matched. It is used only when the
file's size, mtime, ctime, inode and device are all unchanged. Restoring an
mtime (`touch -r`) does not hide a change: writing a file updates its ctime,
which cannot be set from user space, and replacing a file changes its inode.
Every full rehash interval a pass reads every file again, which also covers
clock changes and writes to the block device. SSH targets keep no cache and
read every file on every pass.

## Allowing a change

**Risk › File integrity** lists the changed files grouped by path, status and
actual SHA-256 across hosts. Allowing a group needs a note and takes one of two
scopes:

- **Selected hosts**: the finding is hidden on those hosts only.
- **All hosts with this content**: hidden on every host, including hosts that
  report the same path and SHA-256 later.

A file that changes again has another SHA-256 and is shown again. Revoking a
rule shows the findings it hid at once. Allow rules list who created them and
why; revoked rules stay in the list.

## Limits

- The package database is trusted. A local root user can change files and
  their database entries together.
- dpkg records MD5 digests. They detect changes, but are not a proof against a
  crafted collision.
- Container image content and Windows hosts are not checked.

## Deployment notes

The systemd unit `bomcensus-probe@.service` sets `RuntimeMaxSec=6h` as a
backstop; the probe itself stops a collection after 15 minutes and an
integrity chunk at the end of its window (at most 5 hours).
