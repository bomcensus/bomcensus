// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package proc

import (
	"bufio"
	"cmp"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
)

// Socket states in /proc/net/{tcp,udp}*.
const (
	tcpListen = "0A"
	udpClose  = "07" // bound and not connected
)

type socket struct {
	listen report.Listen
	uid    int
	inode  uint64
}

var socketTables = []struct {
	file, proto, state string
}{
	{"tcp", "tcp", tcpListen},
	{"tcp6", "tcp", tcpListen},
	{"udp", "udp", udpClose},
	{"udp6", "udp", udpClose},
}

// listeners finds the listening sockets of every network namespace seen
// among the processes and attributes them to the processes holding them.
// Sockets nobody visible holds are returned as unowned.
func (c *collector) listeners(ctx context.Context, infos []*procInfo) []report.UnownedPort {
	groups := map[string][]*procInfo{}
	for _, info := range infos {
		if info.netns != "" {
			groups[info.netns] = append(groups[info.netns], info)
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	var unowned []report.UnownedPort
	for _, ns := range keys {
		if ctx.Err() != nil {
			return sortUnowned(unowned)
		}
		members := groups[ns]
		var socks []socket
		read := false
		// Any member's view of the tables is the namespace's view; take the
		// first one that can be read.
		for _, m := range members {
			s, err := readSockets(m.dir)
			if err == nil {
				socks, read = s, true
				break
			}
		}
		if !read {
			c.nsUnread++
			continue
		}
		if len(socks) == 0 {
			continue
		}

		want := make(map[uint64]bool, len(socks))
		for _, s := range socks {
			want[s.inode] = true
		}
		owners := map[uint64][]*procInfo{}
		for _, m := range members {
			if ctx.Err() != nil {
				return sortUnowned(unowned)
			}
			if !m.sockets {
				continue
			}
			inodes, truncated, err := scanSocketFDs(m.dir, want)
			if err != nil {
				if !gone(err) {
					c.sockDenied++
				}
				continue
			}
			if truncated {
				c.fdTruncated++
			}
			for _, ino := range inodes {
				owners[ino] = append(owners[ino], m)
			}
		}

		for _, s := range socks {
			if procs := owners[s.inode]; len(procs) > 0 {
				for _, p := range procs {
					p.p.Listen = append(p.p.Listen, s.listen)
				}
				continue
			}
			unowned = append(unowned, report.UnownedPort{Listen: s.listen, UID: s.uid})
		}
	}

	for _, info := range infos {
		info.p.Listen = sortListen(info.p.Listen)
	}
	return sortUnowned(unowned)
}

// readSockets reads the four socket tables of the network namespace of the
// process in dir. Missing tables (no IPv6) are skipped; at least one must be
// readable.
func readSockets(dir string) ([]socket, error) {
	var all []socket
	var firstErr error
	readAny := false
	for _, t := range socketTables {
		f, err := os.Open(filepath.Join(dir, "net", t.file))
		if err != nil {
			if firstErr == nil && !os.IsNotExist(err) {
				firstErr = err
			}
			continue
		}
		s, err := parseSocketTable(io.LimitReader(f, maxSocketTable), t.proto, t.state)
		f.Close()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		readAny = true
		all = append(all, s...)
	}
	if !readAny {
		if firstErr == nil {
			firstErr = fmt.Errorf("proc: no socket tables in %s", dir)
		}
		return nil, firstErr
	}
	return all, nil
}

// parseSocketTable returns the sockets of one table in the given state.
//
//	sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode
//	 0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 ...
func parseSocketTable(r io.Reader, proto, state string) ([]socket, error) {
	var out []socket
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != state {
			continue
		}
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil || inode == 0 {
			continue
		}
		addr, port, err := decodeSocketAddr(f[1])
		if err != nil {
			continue
		}
		uid, err := strconv.Atoi(f[7])
		if err != nil {
			continue
		}
		out = append(out, socket{
			listen: report.Listen{Proto: proto, Address: addr.String(), Port: port},
			uid:    uid,
			inode:  inode,
		})
	}
	return out, sc.Err()
}

// decodeSocketAddr decodes "ADDR:PORT" from a socket table. The kernel
// prints each 32-bit word of the network-order address as a host-order hex
// number, so the bytes of every word come out in native byte order. The port
// is a host-order hex number. IPv4-mapped IPv6 addresses are reported as
// IPv4.
func decodeSocketAddr(s string) (netip.Addr, int, error) {
	a, p, ok := strings.Cut(s, ":")
	if !ok || (len(a) != 8 && len(a) != 32) {
		return netip.Addr{}, 0, fmt.Errorf("proc: bad socket address %q", s)
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("proc: bad socket port %q", s)
	}
	raw, err := hex.DecodeString(a)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("proc: bad socket address %q", s)
	}
	var b [16]byte
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(b[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	var addr netip.Addr
	if len(raw) == 4 {
		addr = netip.AddrFrom4([4]byte(b[:4]))
	} else {
		addr = netip.AddrFrom16(b).Unmap()
	}
	return addr, int(port), nil
}

// scanSocketFDs returns the inodes in want that the process in dir holds an
// fd for. At most maxFDs entries are looked at.
func scanSocketFDs(dir string, want map[uint64]bool) (inodes []uint64, truncated bool, err error) {
	fdDir := filepath.Join(dir, "fd")
	d, err := os.Open(fdDir)
	if err != nil {
		return nil, false, err
	}
	names, err := d.Readdirnames(maxFDs + 1)
	d.Close()
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	if len(names) > maxFDs {
		names, truncated = names[:maxFDs], true
	}
	seen := map[uint64]bool{}
	for _, n := range names {
		link, err := os.Readlink(filepath.Join(fdDir, n))
		if err != nil {
			continue
		}
		rest, ok := strings.CutPrefix(link, "socket:[")
		if !ok {
			continue
		}
		ino, err := strconv.ParseUint(strings.TrimSuffix(rest, "]"), 10, 64)
		if err != nil || !want[ino] || seen[ino] {
			continue
		}
		seen[ino] = true
		inodes = append(inodes, ino)
	}
	return inodes, truncated, nil
}

func compareListen(a, b report.Listen) int {
	return cmp.Or(
		strings.Compare(a.Proto, b.Proto),
		cmp.Compare(a.Port, b.Port),
		strings.Compare(a.Address, b.Address),
	)
}

func sortListen(l []report.Listen) []report.Listen {
	slices.SortFunc(l, compareListen)
	return slices.Compact(l)
}

func sortUnowned(u []report.UnownedPort) []report.UnownedPort {
	slices.SortFunc(u, func(a, b report.UnownedPort) int {
		return cmp.Or(compareListen(a.Listen, b.Listen), cmp.Compare(a.UID, b.UID))
	})
	return slices.Compact(u)
}
