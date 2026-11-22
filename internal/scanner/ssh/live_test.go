// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package ssh

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/sign/signtest"
)

// The live test runs against real OpenSSH servers in Docker containers. It
// is opt-in (BOMCENSUS_SSH_LIVE=1) because it needs Docker and, for the
// first run, network access to install packages into the images.

const liveLabel = "bomcensus-ssh-live"

var liveImages = map[string]string{
	// BusyBox ash as login shell and /bin/sh.
	"alpine": `FROM alpine:3.20
RUN apk add --no-cache openssh sudo && ssh-keygen -A \
 && adduser -D -s /bin/sh scan && echo 'scan:scanpw' | chpasswd \
 && echo 'scan ALL=(ALL) ALL' > /etc/sudoers.d/scan && chmod 440 /etc/sudoers.d/scan \
 && sed -i -e 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && install -d -m 700 -o scan /home/scan/.ssh
CMD ["/bin/sh", "-c", "echo \"$AUTHORIZED_KEY\" > /home/scan/.ssh/authorized_keys && chown scan /home/scan/.ssh/authorized_keys && exec /usr/sbin/sshd -D -e"]
`,
	// bash as login shell, dash as /bin/sh.
	"debian": `FROM debian:12
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo \
 && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash scan && echo 'scan:scanpw' | chpasswd \
 && echo 'scan ALL=(ALL) ALL' > /etc/sudoers.d/scan && chmod 440 /etc/sudoers.d/scan \
 && echo 'echo bashrc noise' >> /home/scan/.bashrc \
 && install -d -m 700 -o scan /home/scan/.ssh
CMD ["/bin/sh", "-c", "echo \"$AUTHORIZED_KEY\" > /home/scan/.ssh/authorized_keys && chown scan /home/scan/.ssh/authorized_keys && exec /usr/sbin/sshd -D -e"]
`,
}

type liveContainer struct {
	id   string
	port int
	ip   string
}

func docker(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func startLive(t *testing.T, name string, authorized gossh.PublicKey) liveContainer {
	t.Helper()
	image := liveLabel + "-" + name
	docker(t, liveImages[name], "build", "-q", "-t", image, "-")
	// /tmp is noexec so the candidate fallback is exercised; Docker mounts
	// /dev/shm noexec as well.
	id := docker(t, "", "run", "-d", "--rm", "--label", liveLabel+"=1",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"-e", "AUTHORIZED_KEY="+strings.TrimSpace(string(gossh.MarshalAuthorizedKey(authorized))),
		"-p", "127.0.0.1::22", image)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	hostPort := docker(t, "", "port", id, "22/tcp")
	_, p, _ := strings.Cut(strings.Split(hostPort, "\n")[0], ":")
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("docker port output %q", hostPort)
	}
	ip := docker(t, "", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", id)
	return liveContainer{id: id, port: port, ip: ip}
}

func (c liveContainer) leftovers(t *testing.T) string {
	t.Helper()
	out, _ := exec.Command("docker", "exec", c.id, "sh", "-c",
		"find / -xdev -name '"+probeFilePrefix+"*' 2>/dev/null; find /tmp /dev/shm -name '"+probeFilePrefix+"*' 2>/dev/null; ps -ef 2>/dev/null | grep '[.]bomcensus-probe-[0-9a-f]' || true").CombinedOutput()
	return strings.TrimSpace(string(out))
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestLiveOpenSSH(t *testing.T) {
	if os.Getenv("BOMCENSUS_SSH_LIVE") != "1" {
		t.Skip("set BOMCENSUS_SSH_LIVE=1 to run against OpenSSH in Docker")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	tr := signtest.Install(t)
	probe := tr.SignELF(t, fakeProbeELF(t, runtime.GOARCH))
	key, pub := newKey(t)

	alpine := startLive(t, "alpine", pub)
	debian := startLive(t, "debian", pub)

	newDeps := func(logs *lockedBuffer) Deps {
		return Deps{
			Probe:  func(context.Context, string, string) ([]byte, error) { return probe, nil },
			Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		}
	}
	base := func(c liveContainer) Target {
		return Target{
			Address: "127.0.0.1", Port: c.port, User: "scan",
			Auth:    Auth{PrivateKey: key},
			Request: report.Request{Sections: []string{"host"}, Policy: report.DefaultPolicy()},
			Timeout: 2 * time.Minute,
		}
	}
	collect := func(t *testing.T, tg Target) (*Result, string) {
		t.Helper()
		logs := &lockedBuffer{}
		var res *Result
		var err error
		// sshd needs a moment after the container starts.
		for i := 0; i < 30; i++ {
			res, err = Collect(context.Background(), tg, newDeps(logs))
			if err == nil || !strings.Contains(err.Error(), "connect") && !strings.Contains(err.Error(), "handshake") {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("%v\n%s", err, logs)
		}
		return res, logs.String()
	}

	for name, c := range map[string]liveContainer{"alpine": alpine, "debian": debian} {
		t.Run(name, func(t *testing.T) {
			t.Run("key sudo", func(t *testing.T) {
				tg := base(c)
				tg.Sudo = true
				tg.SudoPassword = "scanpw"
				res, logs := collect(t, tg)
				if !res.Privileged || res.SudoFallback != "" || res.Report.Privilege.UID != 0 {
					t.Errorf("privileged %v fallback %q uid %d", res.Privileged, res.SudoFallback, res.Report.Privilege.UID)
				}
				if !strings.Contains(logs, "path=/var/tmp/"+probeFilePrefix) {
					t.Errorf("probe not placed in /var/tmp (noexec /tmp):\n%s", logs)
				}
				if left := c.leftovers(t); left != "" {
					t.Errorf("left on target: %s", left)
				}

				// Pin the key seen on first use.
				tg.HostKey = res.HostKey
				collect(t, tg)
				_, other := newKey(t)
				tg.HostKey = other.Marshal()
				if _, err := Collect(context.Background(), tg, newDeps(&lockedBuffer{})); !errors.Is(err, ErrHostKeyChanged) {
					t.Errorf("pinned mismatch: %v", err)
				}
			})
			t.Run("password no sudo", func(t *testing.T) {
				tg := base(c)
				tg.Auth = Auth{Password: "scanpw"}
				res, _ := collect(t, tg)
				if res.Privileged || res.Report.Privilege.UID == 0 {
					t.Errorf("privileged %v uid %d", res.Privileged, res.Report.Privilege.UID)
				}
			})
			t.Run("wrong sudo password", func(t *testing.T) {
				tg := base(c)
				tg.Sudo = true
				tg.SudoPassword = "wrong"
				res, _ := collect(t, tg)
				if res.Privileged || !strings.Contains(res.SudoFallback, "password rejected") {
					t.Errorf("privileged %v fallback %q", res.Privileged, res.SudoFallback)
				}
			})
			t.Run("no sudo password", func(t *testing.T) {
				tg := base(c)
				tg.Sudo = true
				res, _ := collect(t, tg)
				if res.Privileged || res.SudoFallback == "" {
					t.Errorf("privileged %v fallback %q", res.Privileged, res.SudoFallback)
				}
			})
			t.Run("cancel", func(t *testing.T) {
				tg := base(c)
				tg.Request.Policy.ExcludePaths = []string{"test:sleep"}
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() {
					_, err := Collect(ctx, tg, newDeps(&lockedBuffer{}))
					done <- err
				}()
				deadline := time.Now().Add(30 * time.Second)
				for {
					out, _ := exec.Command("docker", "exec", c.id, "cat", "/home/scan/probe.pid").Output()
					if len(out) > 0 {
						break
					}
					if time.Now().After(deadline) {
						cancel()
						t.Fatal("probe did not start")
					}
					time.Sleep(100 * time.Millisecond)
				}
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Errorf("want context.Canceled, got %v", err)
				}
				_ = exec.Command("docker", "exec", c.id, "rm", "-f", "/home/scan/probe.pid").Run()
				time.Sleep(time.Second)
				if left := c.leftovers(t); left != "" {
					t.Errorf("left on target after cancel: %s", left)
				}
			})
		})
	}
}
