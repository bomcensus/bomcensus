// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package proc

import (
	"slices"
	"strings"
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
)

func TestParseStat(t *testing.T) {
	line := "4242 (my (odd) ) proc) S 17 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000000 200 18446744073709551615\n"
	st, err := parseStat(line)
	if err != nil {
		t.Fatal(err)
	}
	if st.state != 'S' || st.ppid != 17 || st.flags != 4194560 || st.startTicks != 98765 {
		t.Fatalf("got %+v", st)
	}
	if _, err := parseStat("12 (short) S 1 2"); err == nil {
		t.Fatal("short stat accepted")
	}
	if _, err := parseStat("no parenthesis"); err == nil {
		t.Fatal("malformed stat accepted")
	}
}

func TestSplitCmdline(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"\x00\x00", nil},
		{"/usr/bin/app\x00-v\x00", []string{"/usr/bin/app", "-v"}},
		{"/usr/bin/app\x00a b\x00", []string{"/usr/bin/app", "a b"}},
		{"postgres: app db 10.0.0.1(5432) idle", []string{"postgres:", "app", "db", "10.0.0.1(5432)", "idle"}},
	}
	for _, c := range cases {
		if got := splitCmdline([]byte(c.in)); !slices.Equal(got, c.want) {
			t.Errorf("splitCmdline(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMaskCmdline(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/usr/bin/app --password=hunter2 -v", "/usr/bin/app --password=**** -v"},
		{"/usr/bin/app --password hunter2 -v", "/usr/bin/app --password **** -v"},
		{"/usr/bin/app --db-password hunter2", "/usr/bin/app --db-password ****"},
		{"/usr/bin/app --password -v", "/usr/bin/app --password -v"},
		{"/usr/bin/app --token=abc --api-key xyz --apikey=q --client-secret s", "/usr/bin/app --token=**** --api-key **** --apikey=**** --client-secret ****"},
		{"/usr/bin/app --passwd=x --pass y --pwd=z", "/usr/bin/app --passwd=**** --pass **** --pwd=****"},
		{"/usr/bin/app --password-file=/run/secrets/db --token-ttl 24h", "/usr/bin/app --password-file=/run/secrets/db --token-ttl 24h"},
		{"docker login --password-stdin -u me", "docker login --password-stdin -u me"},
		{"psql --no-password mydb", "psql --no-password mydb"},
		{"env PGPASSWORD=s3cret MYSQL_PWD=x AWS_SECRET_ACCESS_KEY=k HOME=/root psql", "env PGPASSWORD=**** MYSQL_PWD=**** AWS_SECRET_ACCESS_KEY=**** HOME=/root psql"},
		{"java -Djavax.net.ssl.keyStorePassword=changeit -Xmx1g -jar app.jar", "java -Djavax.net.ssl.keyStorePassword=**** -Xmx1g -jar app.jar"},
		{"keytool -list -storepass changeit -keypass k2", "keytool -list -storepass **** -keypass ****"},
		{"mysql -uroot -phunter2 -P 3306 db", "mysql -uroot -p**** -P 3306 db"},
		{"/usr/bin/mysqldump -p db", "/usr/bin/mysqldump -p db"},
		{"/usr/bin/tool -phunter2", "/usr/bin/tool -phunter2"},
		{"sshpass -p hunter2 ssh host", "sshpass -p **** ssh host"},
		{"sshpass -phunter2 ssh host", "sshpass -p**** ssh host"},
		{"redis-cli -h db -a hunter2 ping", "redis-cli -h db -a **** ping"},
		{"curl -u admin:hunter2 https://x", "curl -u admin:**** https://x"},
		{"curl -uadmin:hunter2 https://x", "curl -uadmin:**** https://x"},
		{"/app --dsn postgres://app:hunter2@db:5432/app", "/app --dsn postgres://app:****@db:5432/app"},
		{"/app --url=https://u:p%40ss@host/path?q=1", "/app --url=https://u:****@host/path?q=1"},
		{"git clone https://x-access-token:ghp_abc@github.com/o/r", "git clone https://x-access-token:****@github.com/o/r"},
		{"/app http://host:8080/path", "/app http://host:8080/path"},
		{"/app a=b c==d --bypass x", "/app a=b c==d --bypass x"},
	}
	for _, c := range cases {
		if got := maskCmdline(strings.Split(c.in, " ")); got != c.want {
			t.Errorf("mask(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	// A header passed as one argument.
	got := maskCmdline([]string{"curl", "-H", "Authorization: Bearer abc", "https://x"})
	if got != "curl -H Authorization: **** https://x" {
		t.Errorf("header: %q", got)
	}
	// Words of a script passed as one argument, with quotes.
	got = maskCmdline([]string{"sh", "-c", `"$X/server.sh" --port=0 --connection-token=abc '--password' "hunter2" && mysql -phunter2 db`})
	if got != `sh -c "$X/server.sh" --port=0 --connection-token=**** '--password' **** && mysql -p**** db` {
		t.Errorf("script: %q", got)
	}
	// Tool rules apply after a wrapper; a tool name as a password value is
	// still masked.
	got = maskCmdline([]string{"sudo", "-u", "app", "/usr/bin/mysql", "-phunter2"})
	if got != "sudo -u app /usr/bin/mysql -p****" {
		t.Errorf("wrapper: %q", got)
	}
	got = maskCmdline([]string{"/app", "--password", "mysql", "-pfoo"})
	if got != "/app --password **** -pfoo" {
		t.Errorf("tool name as value: %q", got)
	}
	// A value with spaces after a secret option is masked whole.
	got = maskCmdline([]string{"/app", "--password", "two words", "-v"})
	if got != "/app --password **** -v" {
		t.Errorf("spaced value: %q", got)
	}
	// A rewritten title is split into words before masking.
	got = maskCmdline(splitCmdline([]byte("worker --password hunter2")))
	if got != "worker --password ****" {
		t.Errorf("title: %q", got)
	}
	long := maskCmdline([]string{"/app", strings.Repeat("x", maxCmdlineOut*2)})
	if len(long) != maxCmdlineOut {
		t.Errorf("long command line kept %d bytes", len(long))
	}
}

func TestContainerIDFromCgroup(t *testing.T) {
	id := "3f4e2a1b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f"
	outer := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cases := []struct {
		name, in, want string
	}{
		{"docker cgroupfs v1", "12:memory:/docker/" + id + "\n11:cpu,cpuacct:/docker/" + id + "\n", id},
		{"docker systemd v2", "0::/system.slice/docker-" + id + ".scope\n", id},
		{"docker systemd v1", "1:name=systemd:/system.slice/docker-" + id + ".scope\n", id},
		{"cri containerd systemd", "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1a2b3c4d_5e6f_7a8b_9c0d_1e2f3a4b5c6d.slice/cri-containerd-" + id + ".scope\n", id},
		{"cri cgroupfs", "0::/kubepods/burstable/pod1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d/" + id + "\n", id},
		{"crio systemd", "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc.slice/crio-" + id + ".scope\n", id},
		{"crio conmon", "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc.slice/crio-conmon-" + id + ".scope\n", ""},
		{"podman systemd", "0::/machine.slice/libpod-" + id + ".scope/container\n", id},
		{"podman rootless", "0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + id + ".scope\n", id},
		{"podman cgroupfs", "0::/libpod_parent/libpod-" + id + "\n", id},
		{"podman conmon", "0::/machine.slice/libpod-conmon-" + id + ".scope\n", ""},
		{"nested docker", "0::/docker/" + outer + "/docker/" + id + "\n", outer},
		{"v2 preferred", "5:pids:/docker/" + outer + "\n0::/system.slice/docker-" + id + ".scope\n", id},
		{"v1 fallback when v2 is root", "0::/\n4:cpu:/docker/" + id + "\n", id},
		{"host", "0::/user.slice/user-1000.slice/session-2.scope\n", ""},
		{"uppercase is not an id", "0::/docker/" + strings.ToUpper(id) + "\n", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		if got := containerIDFromCgroup(c.in); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDecodeSocketAddr(t *testing.T) {
	cases := []struct {
		in, addr string
		port     int
	}{
		{"0100007F:0CEA", "127.0.0.1", 3306},
		{"00000000:0050", "0.0.0.0", 80},
		{"0101A8C0:01BB", "192.168.1.1", 443},
		{"00000000000000000000000000000000:0016", "::", 22},
		{"00000000000000000000000001000000:1F90", "::1", 8080},
		{"0000000000000000FFFF00000100007F:1F90", "127.0.0.1", 8080},
		{"B80D0120000000000000000001000000:0035", "2001:db8::1", 53},
		{"000080FE00000000FF005450B6AD1DFE:0222", "fe80::5054:ff:fe1d:adb6", 546},
	}
	for _, c := range cases {
		a, p, err := decodeSocketAddr(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if a.String() != c.addr || p != c.port {
			t.Errorf("%s: got %s:%d, want %s:%d", c.in, a, p, c.addr, c.port)
		}
	}
	for _, bad := range []string{"", "0100007F", "0100007:0050", "ZZ00007F:0050", "0100007F:12345"} {
		if _, _, err := decodeSocketAddr(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseSocketTable(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0CEA 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 1004 1 0000000000000000 20 4 30 10 -1
   2: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0
   3: garbage
`
	s, err := parseSocketTable(strings.NewReader(tcp), "tcp", tcpListen)
	if err != nil {
		t.Fatal(err)
	}
	want := []socket{{listen: report.Listen{Proto: "tcp", Address: "127.0.0.1", Port: 3306}, uid: 1000, inode: 1001}}
	if !slices.Equal(s, want) {
		t.Fatalf("got %+v", s)
	}
}

func TestParseMapsLine(t *testing.T) {
	m, ok := parseMapsLine("7f0000a00000-7f0000b00000 r-xp 00001000 08:02 4242                       /opt/my app/lib x.so (deleted)")
	if !ok || m.addr != "7f0000a00000-7f0000b00000" || !m.exec || m.inode != 4242 || m.path != "/opt/my app/lib x.so (deleted)" {
		t.Fatalf("got %+v %v", m, ok)
	}
	m, ok = parseMapsLine("7ffd1c5f2000-7ffd1c5f4000 r-xp 00000000 00:00 0")
	if !ok || m.path != "" {
		t.Fatalf("anonymous: %+v %v", m, ok)
	}
	if _, ok := parseMapsLine("7ffd1c5f2000"); ok {
		t.Fatal("short line accepted")
	}
}

func TestHidepidInMountinfo(t *testing.T) {
	plain := "22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw\n"
	hidden := "22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw,hidepid=invisible\n"
	off := "22 1 0:21 / /proc rw,relatime - proc proc rw,hidepid=0\n"
	if hidepidInMountinfo(plain, "/proc") || hidepidInMountinfo(off, "/proc") {
		t.Error("hidepid reported for a plain mount")
	}
	if !hidepidInMountinfo(hidden, "/proc") {
		t.Error("hidepid not detected")
	}
	if hidepidInMountinfo(hidden, "/other") {
		t.Error("hidepid of another mount point")
	}
}
