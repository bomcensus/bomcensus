// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package container

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
)

// Docker keeps one directory per container and, with a graph driver, its own
// image store:
//
//	<data-root>/containers/<id>/config.v2.json                     container config and state
//	<data-root>/image/<driver>/repositories.json                   tags and repo digests → image id
//	<data-root>/image/<driver>/imagedb/content/sha256/<id>         image config
//	<data-root>/image/<driver>/layerdb/sha256/<chain-id>/size      uncompressed layer size
//	<data-root>/image/<driver>/layerdb/mounts/<container>/mount-id overlay2 directory of the container
//	<data-root>/overlay2/<mount-id>/diff                           writable layer
//
// With the containerd image store (the default for new installs since
// Docker 29) image/ stays empty: images live in containerd's "moby"
// namespace, either in the system containerd or in the one dockerd starts
// under <data-root>/containerd/daemon. config.v2.json then names the image
// by its target digest.
const (
	dockerDefaultDataRoot = "/var/lib/docker"
	dockerDefaultExecRoot = "/var/run/docker"
)

type dockerRoots struct {
	dataRoot, execRoot string
	src                *source
	// readable is set when the container directory could be listed.
	readable bool
}

func (c *collector) findDocker() *dockerRoots {
	d := &dockerRoots{dataRoot: dockerDefaultDataRoot, execRoot: dockerDefaultExecRoot}
	if data, err := c.readFile("/etc/docker/daemon.json", 1<<20); err == nil {
		var cfg struct {
			DataRoot string `json:"data-root"`
			Graph    string `json:"graph"` // removed in Docker 23, still found on old hosts
			ExecRoot string `json:"exec-root"`
		}
		if json.Unmarshal(data, &cfg) == nil {
			for _, v := range []string{cfg.Graph, cfg.DataRoot} {
				if strings.HasPrefix(v, "/") {
					d.dataRoot = v
				}
			}
			if strings.HasPrefix(cfg.ExecRoot, "/") {
				d.execRoot = cfg.ExecRoot
			}
		}
	}
	if !c.exists(d.dataRoot) {
		return nil
	}
	d.src = c.newSource("docker " + d.dataRoot)
	c.runtimes[RuntimeDocker] = true

	// Listing the container directory first tells whether the data root is
	// readable at all; the containerd lookup depends on that.
	p := joinLogical(d.dataRoot, "containers")
	if _, err := c.readDir(p); err == nil || isNotExist(err) {
		d.readable = true
	}
	return d
}

// graphStore is the image store of one graph driver.
type graphStore struct {
	dir     string              // logical <data-root>/image/<driver>
	tags    map[string][]string // image id → normalized tags
	digests map[string][]string // image id → repo digests
}

// digestOf returns the digest an image is reported by: its smallest repo
// digest, or its id when it was never pulled or pushed.
func (g *graphStore) digestOf(id string) string {
	if d := g.digests[id]; len(d) > 0 {
		return slices.Min(d)
	}
	return id
}

func (c *collector) readDocker(d *dockerRoots, roots []*cdRoot) {
	stores := c.graphStores(d)
	findStore := func(id string) *graphStore {
		for _, g := range stores {
			if _, ok := g.tags[id]; ok {
				return g
			}
			if _, ok := g.digests[id]; ok {
				return g
			}
			if c.exists(joinLogical(g.dir, "imagedb/content/sha256", strings.TrimPrefix(id, "sha256:"))) {
				return g
			}
		}
		return nil
	}

	used := map[*graphStore]map[string]bool{}
	p := joinLogical(d.dataRoot, "containers")
	entries, err := c.readDir(p)
	switch {
	case err == nil:
		d.src.read = true
	case isNotExist(err):
		d.src.read = true
	default:
		d.src.fail("container directory", p, err)
	}
	for _, e := range entries {
		if c.done() {
			break
		}
		if !e.IsDir() || !safeName(e.Name()) {
			continue
		}
		ct, imageID, ok := c.dockerContainer(d, e.Name())
		if !ok {
			continue
		}
		if g := findStore(imageID); g != nil {
			ct.ImageDigest = g.digestOf(imageID)
			if used[g] == nil {
				used[g] = map[string]bool{}
			}
			used[g][imageID] = true
		} else if validDigest(imageID) {
			// Containerd image store: the id is the image target.
			ct.ImageDigest = imageID
		}
		if ct.UpperDir == "" {
			ct.UpperDir = c.dockerSnapshotUpper(roots, ct.ID)
		}
		if ct.UpperDir == "" && ct.Running {
			ct.UpperDir = c.upperFromMountinfo(ct.InitPID)
		}
		c.containers = append(c.containers, ct)
	}

	for _, g := range stores {
		ids := map[string]bool{}
		for id := range g.tags {
			ids[id] = true
		}
		for id := range g.digests {
			ids[id] = true
		}
		for id := range used[g] {
			ids[id] = true
		}
		for _, id := range sortedKeys(ids) {
			if c.done() {
				return
			}
			osName, arch, size := c.graphImage(d, g, id)
			mergeImage(c.image(g.digestOf(id)), g.tags[id], osName, arch, size)
		}
	}
}

type dockerConfig struct {
	ID     string `json:"ID"`
	Name   string `json:"Name"`
	Image  string `json:"Image"`
	Driver string `json:"Driver"`
	State  struct {
		Running   bool      `json:"Running"`
		Pid       int       `json:"Pid"`
		StartedAt time.Time `json:"StartedAt"`
	} `json:"State"`
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
}

func (c *collector) dockerContainer(d *dockerRoots, id string) (report.Container, string, bool) {
	p := joinLogical(d.dataRoot, "containers", id, "config.v2.json")
	data, err := c.readFile(p, maxStateFile)
	if err != nil {
		if !isNotExist(err) {
			d.src.fail("container config", p, err)
		}
		return report.Container{}, "", false
	}
	var cfg dockerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		d.src.fail("container config", p, err)
		return report.Container{}, "", false
	}
	if cfg.ID == "" {
		cfg.ID = id
	}
	ct := report.Container{
		ID:       cfg.ID,
		Name:     strings.TrimPrefix(cfg.Name, "/"),
		Runtime:  RuntimeDocker,
		ImageRef: dockerImageRef(cfg.Config.Image, cfg.Image),
	}
	if !cfg.State.StartedAt.IsZero() {
		ct.StartedAt = cfg.State.StartedAt.UTC()
	}
	if cfg.State.Running && c.alive(cfg.State.Pid) {
		ct.Running = true
		ct.InitPID = cfg.State.Pid
	}
	if cfg.Driver == "overlay2" {
		ct.UpperDir = c.overlay2Upper(d, cfg.ID)
	}
	return ct, cfg.Image, true
}

// dockerImageRef normalizes the image the container was created from, unless
// it was given as an image id.
func dockerImageRef(ref, imageID string) string {
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(ref, "sha256:") {
		return ref
	}
	if isHexID(ref) && strings.HasPrefix(strings.TrimPrefix(imageID, "sha256:"), ref) {
		return ref
	}
	return normalizeRef(ref)
}

func (c *collector) overlay2Upper(d *dockerRoots, id string) string {
	p := joinLogical(d.dataRoot, "image/overlay2/layerdb/mounts", id, "mount-id")
	data, err := c.readFile(p, 256)
	if err != nil {
		if !isNotExist(err) {
			d.src.fail("layer mount", p, err)
		}
		return ""
	}
	mountID := strings.TrimSpace(string(data))
	if !safeName(mountID) {
		return ""
	}
	return joinLogical(d.dataRoot, "overlay2", mountID, "diff")
}

// dockerSnapshotUpper finds the writable layer of a container in the
// containerd image store: the snapshot keyed by the container id in the
// "moby" namespace.
func (c *collector) dockerSnapshotUpper(roots []*cdRoot, id string) string {
	for _, r := range roots {
		if r.meta == nil {
			continue
		}
		ns := r.meta.namespaces[dockerNamespace]
		if ns == nil {
			continue
		}
		for _, sn := range sortedKeys(ns.snapshots) {
			if name, ok := ns.snapshots[sn][id]; ok {
				if up := c.snapshotUpper(r, sn, name); up != "" {
					return up
				}
			}
		}
	}
	return ""
}

// graphStores reads repositories.json of every graph driver directory.
func (c *collector) graphStores(d *dockerRoots) []*graphStore {
	base := joinLogical(d.dataRoot, "image")
	entries, err := c.readDir(base)
	if err != nil {
		if !isNotExist(err) {
			d.src.fail("image directory", base, err)
		}
		return nil
	}
	var out []*graphStore
	for _, e := range entries {
		if !e.IsDir() || !safeName(e.Name()) {
			continue
		}
		g := &graphStore{dir: joinLogical(base, e.Name()), tags: map[string][]string{}, digests: map[string][]string{}}
		p := joinLogical(g.dir, "repositories.json")
		data, err := c.readFile(p, maxStateFile)
		if err != nil {
			if !isNotExist(err) {
				d.src.fail("image repositories", p, err)
			}
			continue
		}
		var repos struct {
			Repositories map[string]map[string]string `json:"Repositories"`
		}
		if err := json.Unmarshal(data, &repos); err != nil {
			d.src.fail("image repositories", p, err)
			continue
		}
		d.src.read = true
		for _, refs := range repos.Repositories {
			for ref, id := range refs {
				if !validDigest(id) {
					continue
				}
				if _, dg, ok := strings.Cut(ref, "@"); ok {
					if validDigest(dg) {
						g.digests[id] = append(g.digests[id], dg)
					}
					continue
				}
				g.tags[id] = append(g.tags[id], normalizeRef(ref))
			}
		}
		out = append(out, g)
	}
	return out
}

// graphImage reads os, architecture and size of a graph driver image. The
// size is the sum of the uncompressed layers, as `docker images` shows it.
func (c *collector) graphImage(d *dockerRoots, g *graphStore, id string) (osName, arch string, size int64) {
	hexID := strings.TrimPrefix(id, "sha256:")
	p := joinLogical(g.dir, "imagedb/content/sha256", hexID)
	data, err := c.readFile(p, maxStateFile)
	if err != nil {
		if !isNotExist(err) {
			d.src.fail("image config", p, err)
		}
		return "", "", 0
	}
	var cfg struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		RootFS       struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		d.src.fail("image config", p, err)
		return "", "", 0
	}
	for _, chain := range chainIDs(cfg.RootFS.DiffIDs) {
		sp := joinLogical(g.dir, "layerdb/sha256", strings.TrimPrefix(chain, "sha256:"), "size")
		raw, err := c.readFile(sp, 64)
		if err != nil {
			return cfg.OS, cfg.Architecture, 0
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			return cfg.OS, cfg.Architecture, 0
		}
		size += n
	}
	return cfg.OS, cfg.Architecture, size
}

// chainIDs computes the OCI chain ids of a layer stack:
// chain(0) = diff(0), chain(n) = sha256(chain(n-1) + " " + diff(n)).
func chainIDs(diffIDs []string) []string {
	out := make([]string, 0, len(diffIDs))
	for i, d := range diffIDs {
		if !validDigest(d) {
			return nil
		}
		if i == 0 {
			out = append(out, d)
			continue
		}
		sum := sha256.Sum256([]byte(out[i-1] + " " + d))
		out = append(out, fmt.Sprintf("sha256:%s", hex.EncodeToString(sum[:])))
	}
	return out
}
