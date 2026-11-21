// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package normalize

import (
	"reflect"
	"testing"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

var (
	ubuntu = Distro{ID: "ubuntu", VersionID: "24.04", IDLike: []string{"debian"}}
	debian = Distro{ID: "debian", VersionID: "12"}
	rocky  = Distro{ID: "rocky", VersionID: "9.3", IDLike: []string{"rhel", "centos", "fedora"}}
	rhel   = Distro{ID: "rhel", VersionID: "9.4", IDLike: []string{"fedora"}}
	alpine = Distro{ID: "alpine", VersionID: "3.19.1"}
)

func TestEscape(t *testing.T) {
	cases := map[string]string{
		"1:2.4.47-2+b1":  "1:2.4.47-2%2Bb1",
		"1.0~rc1":        "1.0~rc1",
		"a b/c?d#e&f=g@": "a%20b%2Fc%3Fd%23e%26f%3Dg%40",
		"ü":              "%C3%BC",
		"v0.0.0-2023+in": "v0.0.0-2023%2Bin",
	}
	for in, want := range cases {
		if got := Escape(in); got != want {
			t.Errorf("Escape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPackagePURL(t *testing.T) {
	cases := []struct {
		name string
		p    report.Package
		d    Distro
		want string
	}{
		{"deb", report.Package{Type: "deb", Name: "curl", Version: "8.5.0-2ubuntu10.1", Arch: "amd64"}, ubuntu,
			"pkg:deb/ubuntu/curl@8.5.0-2ubuntu10.1?arch=amd64&distro=ubuntu-24.04"},
		{"deb epoch and plus", report.Package{Type: "deb", Name: "attr", Version: "1:2.4.47-2+b1", Arch: "amd64"}, debian,
			"pkg:deb/debian/attr@1:2.4.47-2%2Bb1?arch=amd64&distro=debian-12"},
		{"deb uppercase name", report.Package{Type: "deb", Name: "LibFoo", Version: "1.0", Arch: "all"}, debian,
			"pkg:deb/debian/libfoo@1.0?arch=all&distro=debian-12"},
		{"rpm epoch", report.Package{Type: "rpm", Name: "openssl", Version: "1:3.0.7-27.el9", Arch: "x86_64"}, rocky,
			"pkg:rpm/rocky/openssl@3.0.7-27.el9?arch=x86_64&distro=rocky-9.3&epoch=1"},
		{"rpm no epoch keeps case", report.Package{Type: "rpm", Name: "NetworkManager", Version: "1.46.0-4.el9", Arch: "x86_64"}, rhel,
			"pkg:rpm/rhel/NetworkManager@1.46.0-4.el9?arch=x86_64&distro=rhel-9.4"},
		{"apk", report.Package{Type: "apk", Name: "musl", Version: "1.2.4_git20230717-r4", Arch: "x86_64"}, alpine,
			"pkg:apk/alpine/musl@1.2.4_git20230717-r4?arch=x86_64&distro=alpine-3.19.1"},
		{"unknown distro", report.Package{Type: "deb", Name: "bash", Version: "5.2-1"}, Distro{},
			"pkg:deb/unknown/bash@5.2-1"},
		{"distro without version", report.Package{Type: "apk", Name: "busybox", Version: "1.36.1-r0", Arch: "aarch64"},
			Distro{ID: "wolfi"}, "pkg:apk/wolfi/busybox@1.36.1-r0?arch=aarch64&distro=wolfi"},
	}
	for _, c := range cases {
		if got := Package(c.p, c.d).PURL; got != c.want {
			t.Errorf("%s: purl %q, want %q", c.name, got, c.want)
		}
	}
}

func TestPackageComponent(t *testing.T) {
	got := Package(report.Package{Type: "rpm", Name: "openssl", Version: "1:3.0.7-27.el9", Arch: "x86_64",
		SourceName: "openssl", SourceVersion: "3.0.7-27.el9", Vendor: "Rocky Enterprise Software Foundation"}, rocky)
	want := store.Component{Type: "rpm", Name: "openssl", Version: "1:3.0.7-27.el9", Arch: "x86_64",
		Distro: "rocky-9.3", PURL: "pkg:rpm/rocky/openssl@3.0.7-27.el9?arch=x86_64&distro=rocky-9.3&epoch=1",
		SourceName: "openssl", SourceVersion: "3.0.7-27.el9", Vendor: "Rocky Enterprise Software Foundation",
		Origin: store.OriginDistro}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	// dpkg leaves Source out when it equals the package.
	d := Package(report.Package{Type: "deb", Name: "bash", Version: "5.2.21-2ubuntu4", Maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"}, ubuntu)
	if d.SourceName != "bash" || d.SourceVersion != "5.2.21-2ubuntu4" || d.Vendor == "" {
		t.Errorf("deb source/vendor: %+v", d)
	}
}

func TestOriginRules(t *testing.T) {
	cases := []struct {
		name   string
		p      report.Package
		d      Distro
		origin store.ComponentOrigin
		rule   string
	}{
		{"rocky vendor .el9", report.Package{Type: "rpm", Name: "bash", Version: "5.1.8-9.el9",
			Vendor: "Rocky Enterprise Software Foundation"}, rocky, store.OriginDistro, "rocky-vendor"},
		{"rhel vendor", report.Package{Type: "rpm", Name: "bash", Version: "5.1.8-9.el9",
			Vendor: "Red Hat, Inc."}, rhel, store.OriginDistro, "rhel-vendor"},
		{"alma vendor", report.Package{Type: "rpm", Name: "bash", Version: "5.1.8-9.el9",
			Vendor: "AlmaLinux"}, Distro{ID: "almalinux", VersionID: "9.4"}, store.OriginDistro, "alma-vendor"},
		{"epel on rocky", report.Package{Type: "rpm", Name: "htop", Version: "3.3.0-1.el9",
			Vendor: "Fedora Project"}, rocky, store.OriginThirdParty, "rpm-foreign-vendor"},
		{"fedora on fedora", report.Package{Type: "rpm", Name: "htop", Version: "3.3.0-1.fc40",
			Vendor: "Fedora Project"}, Distro{ID: "fedora", VersionID: "40"}, store.OriginDistro, "fedora-vendor"},
		{"nginx.org rpm", report.Package{Type: "rpm", Name: "nginx", Version: "1:1.26.1-2.el9.ngx",
			Vendor: "Nginx, Inc."}, rocky, store.OriginThirdParty, "nginx-org"},
		{"docker-ce rpm", report.Package{Type: "rpm", Name: "docker-ce", Version: "3:26.1.4-1.el9",
			Vendor: "Docker"}, rhel, store.OriginThirdParty, "docker"},
		{"rpm without vendor", report.Package{Type: "rpm", Name: "local", Version: "1.0-1.el9"}, rocky,
			store.OriginDistro, DefaultRule},
		{"ubuntu maintainer", report.Package{Type: "deb", Name: "bash", Version: "5.2.21-2ubuntu4",
			Maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"}, ubuntu, store.OriginDistro, "ubuntu-maintainer"},
		{"debian maintainer on ubuntu", report.Package{Type: "deb", Name: "zlib1g", Version: "1:1.3.dfsg-3.1",
			Maintainer: "Mark Brown <broonie@debian.org>"}, ubuntu, store.OriginDistro, "debian-maintainer"},
		{"ubuntu release tag", report.Package{Type: "deb", Name: "foo", Version: "1.0-1ubuntu2",
			Maintainer: "Someone <someone@example.com>"}, ubuntu, store.OriginDistro, "ubuntu-release"},
		{"debian security release", report.Package{Type: "deb", Name: "foo", Version: "1.0-1+deb12u1",
			Maintainer: "Someone <someone@example.com>"}, debian, store.OriginDistro, "debian-release"},
		{"nginx.org deb", report.Package{Type: "deb", Name: "nginx", Version: "1.26.1-2~noble",
			Maintainer: "NGINX Packaging <nginx-packaging@f5.com>"}, ubuntu, store.OriginThirdParty, "nginx-org"},
		{"docker deb", report.Package{Type: "deb", Name: "docker-ce", Version: "5:26.1.4-1~ubuntu.24.04~noble",
			Maintainer: "Docker <support@docker.com>"}, ubuntu, store.OriginThirdParty, "docker"},
		{"debian docker.io", report.Package{Type: "deb", Name: "docker.io", Version: "20.10.24+dfsg1-1+b3",
			Maintainer: "Debian Go Packaging Team <team+pkg-go@tracker.debian.org>"}, debian, store.OriginDistro, "debian-maintainer"},
		{"codename suffix", report.Package{Type: "deb", Name: "tool", Version: "2.1-1~jammy"}, ubuntu,
			store.OriginThirdParty, "deb-codename-suffix"},
		{"ppa keeps ubuntu maintainer", report.Package{Type: "deb", Name: "tool", Version: "2.1-0ubuntu1~ppa1",
			Maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"}, ubuntu, store.OriginThirdParty, "ppa"},
		{"pgdg deb", report.Package{Type: "deb", Name: "postgresql-16", Version: "16.3-1.pgdg120+1",
			Maintainer: "Debian PostgreSQL Maintainers <team+postgresql@tracker.debian.org>"}, debian, store.OriginThirdParty, "pgdg-release"},
		{"alpine maintainer", report.Package{Type: "apk", Name: "musl", Version: "1.2.4-r2",
			Maintainer: "Timo Teräs <timo.teras@iki.fi>"}, alpine, store.OriginDistro, DefaultRule},
		{"alpine team", report.Package{Type: "apk", Name: "apk-tools", Version: "2.14.0-r5",
			Maintainer: "Natanael Copa <ncopa@alpinelinux.org>"}, alpine, store.OriginDistro, "alpine-maintainer"},
		{"rpm on debian", report.Package{Type: "rpm", Name: "foo", Version: "1.0-1"}, debian,
			store.OriginThirdParty, DefaultRule},
		{"deb with unknown os", report.Package{Type: "deb", Name: "foo", Version: "1.0-1"}, Distro{},
			store.OriginDistro, DefaultRule},
		{"azure linux microsoft", report.Package{Type: "rpm", Name: "bash", Version: "5.2.15-1.azl3",
			Vendor: "Microsoft Corporation"}, Distro{ID: "azurelinux", VersionID: "3.0"}, store.OriginDistro, "azure-linux-vendor"},
		{"microsoft repo on ubuntu", report.Package{Type: "deb", Name: "powershell", Version: "7.4.2-1.deb",
			Maintainer: "PowerShell Team <PowerShellTeam@hotmail.com>", Vendor: "Microsoft Corporation"}, ubuntu,
			store.OriginThirdParty, "microsoft"},
	}
	for _, c := range cases {
		origin, rule := ClassifyOrigin(c.p, c.d)
		if origin != c.origin || rule != c.rule {
			t.Errorf("%s: got %s (%s), want %s (%s)", c.name, origin, rule, c.origin, c.rule)
		}
	}
}

func TestArtifactPURL(t *testing.T) {
	cases := []struct {
		name string
		a    report.Artifact
		want []string
	}{
		{"maven", report.Artifact{Kind: "jar", GroupID: "org.apache.logging.log4j", ArtifactID: "log4j-core", Version: "2.14.1"},
			[]string{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}},
		{"jar without coordinates", report.Artifact{Kind: "jar", Name: "legacy-lib", Version: "1.0"},
			[]string{"pkg:generic/legacy-lib@1.0"}},
		{"go binary", report.Artifact{Kind: "go_binary", Name: "app", Module: "github.com/Example/App", Version: "v1.2.3",
			GoVersion: "go1.22.1 X:boringcrypto"},
			[]string{"pkg:golang/github.com/Example/App@v1.2.3", "pkg:golang/stdlib@1.22.1"}},
		{"go binary devel", report.Artifact{Kind: "go_binary", Name: "tool", Module: "example.com/tool", Version: "(devel)", GoVersion: "go1.23.0"},
			[]string{"pkg:golang/example.com/tool", "pkg:golang/stdlib@1.23.0"}},
		{"go module incompatible", report.Artifact{Kind: "go_module", Module: "github.com/docker/docker", Version: "v24.0.7+incompatible"},
			[]string{"pkg:golang/github.com/docker/docker@v24.0.7%2Bincompatible"}},
		{"software with detector purl", report.Artifact{Kind: "software", Name: "nginx", Version: "1.25.3", PURL: "pkg:generic/nginx@1.25.3"},
			[]string{"pkg:generic/nginx@1.25.3"}},
		{"software without purl", report.Artifact{Kind: "software", Name: "tibero", Version: "7 FS02"},
			[]string{"pkg:generic/tibero@7%20FS02"}},
		{"software empty version template", report.Artifact{Kind: "software", Name: "node", PURL: "pkg:generic/node@"},
			[]string{"pkg:generic/node"}},
	}
	for _, c := range cases {
		var got []string
		for _, comp := range Artifact(c.a) {
			got = append(got, comp.PURL)
			if comp.Origin != store.OriginUpstream {
				t.Errorf("%s: origin %s", c.name, comp.Origin)
			}
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestBuildContentLinksOwnedArtifacts(t *testing.T) {
	pkgs := []report.Package{
		{Type: "deb", Name: "libjackson2-core-java", Version: "2.14.1-1", Arch: "all"},
		{Type: "deb", Name: "containerd", Version: "1.7.12-0ubuntu4", Arch: "amd64"},
	}
	arts := []report.Artifact{
		{Kind: "jar", Path: "/usr/share/java/jackson-core.jar", GroupID: "com.fasterxml.jackson.core",
			ArtifactID: "jackson-core", Version: "2.14.1", OwnerPackage: "libjackson2-core-java"},
		{Kind: "go_binary", Path: "/usr/bin/containerd", Module: "github.com/containerd/containerd",
			Version: "v1.7.12", SHA256: "aa", OwnerPackage: "containerd:amd64", InUse: true},
		{Kind: "go_binary", Path: "/opt/app/app", Name: "app", Module: "example.com/app", Version: "v1.0.0",
			GoVersion: "go1.22.1", SHA256: "bb"},
		{Kind: "go_module", Path: "/opt/app/app", Module: "golang.org/x/net", Version: "v0.20.0"},
		{Kind: "jar", Path: "/opt/app/app.jar", Nested: []string{"BOOT-INF/lib/spring-core-6.1.0.jar"},
			GroupID: "org.springframework", ArtifactID: "spring-core", Version: "6.1.0"},
	}
	c := BuildContent(pkgs, arts, ubuntu)
	if len(c.Packages) != 2 || len(c.Artifacts) != 4 {
		t.Fatalf("packages %d artifacts %d", len(c.Packages), len(c.Artifacts))
	}
	if got := c.Packages[0].Locations; !reflect.DeepEqual(got, []string{"/usr/share/java/jackson-core.jar"}) {
		t.Errorf("jackson locations %q", got)
	}
	if !c.Packages[1].InUse || !reflect.DeepEqual(c.Packages[1].Locations, []string{"/usr/bin/containerd"}) {
		t.Errorf("containerd %+v", c.Packages[1])
	}
	var nested string
	for _, a := range c.Artifacts {
		if a.Component.Name == "org.springframework:spring-core" {
			nested = a.Locations[0]
		}
	}
	if nested != "/opt/app/app.jar!/BOOT-INF/lib/spring-core-6.1.0.jar" {
		t.Errorf("nested location %q", nested)
	}
	if len(c.Hashes) != 2 || c.Hashes[0].Component.Name != "containerd" || c.Hashes[1].Component.Name != "example.com/app" {
		t.Errorf("hashes %+v", c.Hashes)
	}
}

func TestImageDigestAndTag(t *testing.T) {
	for in, want := range map[string]string{
		"docker-pullable://nginx@sha256:abc": "sha256:abc",
		"docker.io/library/nginx@sha256:abc": "sha256:abc",
		"sha256:abc":                         "sha256:abc",
		"docker://sha256:abc":                "sha256:abc",
	} {
		if got := ImageDigest(in); got != want {
			t.Errorf("ImageDigest(%q) = %q", in, got)
		}
	}
	for in, want := range map[string]string{
		"nginx:1.25":                     "nginx:1.25",
		"registry:5000/app:1@sha256:abc": "registry:5000/app:1",
		"registry:5000/app@sha256:abc":   "",
		"docker.io/library/nginx":        "docker.io/library/nginx",
	} {
		if got := ImageTag(in); got != want {
			t.Errorf("ImageTag(%q) = %q, want %q", in, got, want)
		}
	}
}
