// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

//go:build linux

package container

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/bomcensus/bomcensus/internal/report"
)

// containerd keeps its persistent state under a root directory and its
// runtime state (running tasks) under a state directory:
//
//	<root>/io.containerd.metadata.v1.bolt/meta.db          images, containers, snapshot keys (bbolt)
//	<root>/io.containerd.content.v1.content/blobs/sha256/  index, manifest and config blobs
//	<root>/io.containerd.snapshotter.v1.overlayfs/         metadata.db (bbolt) and snapshots/<id>/fs
//	<root>/io.containerd.grpc.v1.cri/containers/<id>/status CRI container status (JSON)
//	<state>/io.containerd.runtime.v2.task/<ns>/<id>/       init.pid, config.json (OCI spec)
const (
	cdMetaDB       = "io.containerd.metadata.v1.bolt/meta.db"
	cdBlobs        = "io.containerd.content.v1.content/blobs"
	cdSnapshotter  = "io.containerd.snapshotter.v1."
	cdCRIContainer = "io.containerd.grpc.v1.cri/containers"
	cdTasks        = "io.containerd.runtime.v2.task"
)

// dockerNamespace is the containerd namespace Docker uses. Its containers are
// reported from Docker's own state; its images are Docker's images when the
// containerd image store is enabled.
const dockerNamespace = "moby"

// CRI labels on containerd containers.
const (
	labelCRIKind      = "io.cri-containerd.kind"
	labelPodNamespace = "io.kubernetes.pod.namespace"
	labelPodName      = "io.kubernetes.pod.name"
	labelContainer    = "io.kubernetes.container.name"
	labelNerdctlName  = "nerdctl/name"
)

// CRI annotations in the OCI spec of a task.
const (
	annContainerType = "io.kubernetes.cri.container-type"
	annContainerName = "io.kubernetes.cri.container-name"
	annSandboxName   = "io.kubernetes.cri.sandbox-name"
	annSandboxNS     = "io.kubernetes.cri.sandbox-namespace"
	annImageName     = "io.kubernetes.cri.image-name"
)

// cdRoot is one containerd installation.
type cdRoot struct {
	root, state string // logical paths
	// docker is set for the containerd that dockerd starts itself under its
	// data root. It is part of Docker, not a separate runtime.
	docker bool
	src    *source
	meta   *cdMeta
	// snapIDs caches snapshotter metadata: snapshotter → backend name → id.
	snapIDs map[string]map[string]string
	// platforms caches image details by target digest.
	platforms map[string]imageDetails
	// chains caches the top chain ids of an image target.
	chains map[string]imageChains
}

type cdMeta struct {
	namespaces map[string]*cdNamespace
}

type cdNamespace struct {
	images     map[string]string // image name → target digest
	containers []cdContainer
	// snapshots maps snapshotter → snapshot key → backend name.
	snapshots map[string]map[string]string
	// parents maps snapshotter → snapshot key → parent snapshot key.
	parents map[string]map[string]string
}

type cdContainer struct {
	id, image, snapshotter, snapshotKey string
	labels                              map[string]string
}

type imageDetails struct {
	os, arch string
	size     int64
}

// findContainerd lists the containerd installations whose directories exist.
func (c *collector) findContainerd(dock *dockerRoots) []*cdRoot {
	type pair struct{ root, state string }
	var cands []pair
	root, state := c.containerdConfig()
	cands = append(cands,
		pair{root, state},
		pair{"/var/lib/rancher/k3s/agent/containerd", "/run/k3s/containerd"},
		pair{"/var/lib/rancher/rke2/agent/containerd", "/run/k3s/containerd"},
	)
	var out []*cdRoot
	seen := map[string]bool{}
	for _, p := range cands {
		if seen[p.root] || !c.exists(p.root) {
			continue
		}
		seen[p.root] = true
		r := &cdRoot{root: p.root, state: p.state}
		r.src = c.newSource(fmt.Sprintf("containerd %s", p.root))
		c.runtimes[RuntimeContainerd] = true
		out = append(out, r)
	}
	if dock != nil && dock.readable {
		root := joinLogical(dock.dataRoot, "containerd", "daemon")
		if !seen[root] && c.exists(root) {
			r := &cdRoot{root: root, state: joinLogical(dock.execRoot, "containerd", "daemon"), docker: true}
			r.src = c.newSource(fmt.Sprintf("docker containerd %s", root))
			out = append(out, r)
		}
	}
	return out
}

// containerdConfig returns root and state from /etc/containerd/config.toml,
// or the defaults. Only the top-level keys are read.
func (c *collector) containerdConfig() (root, state string) {
	root, state = "/var/lib/containerd", "/run/containerd"
	data, err := c.readFile("/etc/containerd/config.toml", 1<<20)
	if err != nil {
		return root, state
	}
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if !strings.HasPrefix(v, "/") {
			continue
		}
		switch strings.TrimSpace(k) {
		case "root":
			root = v
		case "state":
			state = v
		}
	}
	return root, state
}

func (c *collector) readContainerd(r *cdRoot) {
	metaPath := joinLogical(r.root, cdMetaDB)
	meta, err := c.readMeta(metaPath)
	switch {
	case err == nil:
		r.meta = meta
		r.src.read = true
	case isNotExist(err):
		// No database yet: nothing was ever pulled or created.
		r.src.read = true
	default:
		r.src.fail("metadata database", metaPath, err)
	}

	if r.meta != nil {
		c.containerdImages(r)
		if !r.docker {
			c.containerdContainers(r)
		}
		return
	}
	if !r.docker {
		c.containerdTasks(r)
	}
}

// readMeta reads the parts of containerd's metadata database the inventory
// needs. Layout: v1/<namespace>/{images,containers,snapshots}. A snapshot is
// v1/<namespace>/snapshots/<snapshotter>/<key> with "name" (the backend
// name) and "parent" (the key of the parent snapshot).
func (c *collector) readMeta(logical string) (*cdMeta, error) {
	db, err := openBoltCopy(c.env.Path(logical))
	if err != nil {
		return nil, err
	}
	defer db.Close()

	meta := &cdMeta{namespaces: map[string]*cdNamespace{}}
	err = boltView(db, func(tx *bolt.Tx) error {
		v1 := tx.Bucket([]byte("v1"))
		if v1 == nil {
			return nil
		}
		return v1.ForEachBucket(func(name []byte) error {
			nsb := v1.Bucket(name)
			ns := &cdNamespace{
				images:    map[string]string{},
				snapshots: map[string]map[string]string{},
				parents:   map[string]map[string]string{},
			}
			meta.namespaces[string(name)] = ns

			if ib := nsb.Bucket([]byte("images")); ib != nil {
				_ = ib.ForEachBucket(func(k []byte) error {
					d := bucketString(ib.Bucket(k).Bucket([]byte("target")), "digest")
					if validDigest(d) {
						ns.images[string(k)] = d
					}
					return nil
				})
			}
			if cb := nsb.Bucket([]byte("containers")); cb != nil {
				_ = cb.ForEachBucket(func(k []byte) error {
					b := cb.Bucket(k)
					ns.containers = append(ns.containers, cdContainer{
						id:          string(k),
						image:       bucketString(b, "image"),
						snapshotter: bucketString(b, "snapshotter"),
						snapshotKey: bucketString(b, "snapshotKey"),
						labels:      bucketStrings(b.Bucket([]byte("labels"))),
					})
					return nil
				})
			}
			if sb := nsb.Bucket([]byte("snapshots")); sb != nil {
				_ = sb.ForEachBucket(func(sn []byte) error {
					keys, parents := map[string]string{}, map[string]string{}
					snb := sb.Bucket(sn)
					_ = snb.ForEachBucket(func(k []byte) error {
						kb := snb.Bucket(k)
						if n := bucketString(kb, "name"); n != "" {
							keys[string(k)] = n
						}
						if p := bucketString(kb, "parent"); p != "" {
							parents[string(k)] = p
						}
						return nil
					})
					ns.snapshots[string(sn)] = keys
					ns.parents[string(sn)] = parents
					return nil
				})
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return meta, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// containerdImages adds every image of every namespace. Names that pin a
// digest ("repo@sha256:…", "sha256:<config>") are aliases CRI creates and
// are not repo tags.
func (c *collector) containerdImages(r *cdRoot) {
	byTarget := map[string][]string{}
	for _, nsName := range sortedKeys(r.meta.namespaces) {
		for name, target := range r.meta.namespaces[nsName].images {
			tags := byTarget[target]
			if !isDigestRef(name) {
				tags = append(tags, normalizeRef(name))
			}
			byTarget[target] = tags
		}
	}
	for _, target := range sortedKeys(byTarget) {
		if c.done() {
			return
		}
		d := c.imageDetails(r, target)
		mergeImage(c.image(target), byTarget[target], d.os, d.arch, d.size)
	}
}

func (c *collector) containerdContainers(r *cdRoot) {
	for _, nsName := range sortedKeys(r.meta.namespaces) {
		if nsName == dockerNamespace {
			continue
		}
		ns := r.meta.namespaces[nsName]
		for _, mc := range ns.containers {
			if c.done() {
				return
			}
			if mc.labels[labelCRIKind] == "sandbox" || !safeName(mc.id) {
				continue
			}
			ct := report.Container{
				ID:       mc.id,
				Name:     containerName(mc.id, mc.labels),
				Runtime:  RuntimeContainerd,
				ImageRef: normalizeRef(mc.image),
			}
			ct.ImageDigest, ct.Reason = c.containerImage(r, ns, mc, ct.ImageRef)
			c.taskState(r, nsName, &ct)
			if mc.labels[labelCRIKind] != "" {
				c.criStatus(r, &ct)
			}
			if name, ok := ns.snapshots[mc.snapshotter][mc.snapshotKey]; ok {
				ct.UpperDir = c.snapshotUpper(r, mc.snapshotter, name)
			}
			if ct.UpperDir == "" && ct.Running {
				ct.UpperDir = c.upperFromMountinfo(ct.InitPID)
			}
			c.containers = append(c.containers, ct)
		}
	}
}

// unverified starts the reason given for a container whose image digest is
// left empty.
const unverified = "image digest could not be verified: "

// containerImage returns the digest of the image a container runs, or an
// empty digest and the reason.
//
// The container record names its image, and the image table maps the name to
// the image's current target. When the name was pulled again after the
// container was created, it points at an image the container does not run,
// and that image would be credited with the container's root. So the name is
// checked against the container's snapshot: containerd prepares it on top of
// the committed snapshot of the image's top layer, whose key is the chain id
// of the image's layers (client.WithNewSnapshot; WithRemappedSnapshot puts
// one more committed snapshot in between). The parent is recorded in the
// metadata database whatever the snapshotter is.
//
// When the named image does not match, another image of the namespace that
// does is used: CRI keeps "repo@sha256:…" and "sha256:<config>" names, so the
// image is often still there under another name. When nothing matches the
// digest stays empty, and the probe then reads only the writable layer and
// credits no image. This includes the cases where a match can be neither
// shown nor ruled out: a container without a snapshot, and images whose
// manifest or config is not in the content store.
func (c *collector) containerImage(r *cdRoot, ns *cdNamespace, mc cdContainer, ref string) (digest, reason string) {
	named := ns.images[mc.image]
	if named == "" && ref != mc.image {
		named = ns.images[ref]
	}
	top, why := snapshotParent(ns, mc)
	if why != "" {
		return "", unverified + why
	}
	readable := false
	if named != "" {
		ch := c.imageChains(r, named)
		if slices.Contains(ch.tops, top) {
			return named, ""
		}
		readable = ch.readable
	}
	targets := map[string]bool{}
	for _, t := range ns.images {
		if t != named {
			targets[t] = true
		}
	}
	// Images with the same top chain id have the same root file system; the
	// lowest digest is taken so that the result is stable. Every image
	// without layers has the empty top, so for those only the named image
	// is taken.
	if top == "" {
		clear(targets)
	}
	for _, t := range sortedKeys(targets) {
		if c.done() {
			return "", unverified + "collection interrupted"
		}
		if slices.Contains(c.imageChains(r, t).tops, top) {
			return t, ""
		}
	}
	switch {
	case named == "":
		return "", unverified + "the image of the container is not in the image store"
	case !readable:
		return "", unverified + "the image config of " + named + " could not be read"
	}
	return "", unverified + "the container's layers are not those of " + named + " or of any other image"
}

// snapshotParent returns the parent of a container's snapshot: the chain id
// of the top layer of its image, or "" for an image without layers. When the
// parent cannot be found it returns why.
func snapshotParent(ns *cdNamespace, mc cdContainer) (top, why string) {
	if _, ok := ns.snapshots[mc.snapshotter][mc.snapshotKey]; !ok || mc.snapshotKey == "" {
		return "", "the container has no snapshot"
	}
	parents := ns.parents[mc.snapshotter]
	p := parents[mc.snapshotKey]
	if p != "" && !validDigest(p) {
		// A remapped snapshot for user namespaces ("<chain id>-<uid>-<gid>"),
		// committed on top of the image's snapshot.
		if p = parents[p]; p == "" {
			return "", "the remapped snapshot of the container has no parent"
		}
	}
	return p, ""
}

// containerName is "<pod namespace>/<pod>/<container>" for Kubernetes
// containers, the nerdctl name when there is one, else the id.
func containerName(id string, labels map[string]string) string {
	if n := labels[labelContainer]; n != "" && labels[labelPodName] != "" {
		return labels[labelPodNamespace] + "/" + labels[labelPodName] + "/" + n
	}
	if n := labels[labelNerdctlName]; n != "" {
		return n
	}
	return id
}

// taskState fills InitPID, Running and (as a fallback) StartedAt from the
// task directory. The task directory exists only while a task exists.
func (c *collector) taskState(r *cdRoot, ns string, ct *report.Container) {
	p := joinLogical(r.state, cdTasks, ns, ct.ID, "init.pid")
	data, err := c.readFile(p, 64)
	if err != nil {
		if !isNotExist(err) {
			r.src.fail("task state", p, err)
		}
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || !c.alive(pid) {
		return
	}
	ct.Running = true
	ct.InitPID = pid
	// init.pid is written when the task is created, right before it starts.
	if fi, err := c.env.Open(p); err == nil {
		if st, err := fi.Stat(); err == nil {
			ct.StartedAt = st.ModTime().UTC()
		}
		fi.Close()
	}
}

// criStatus reads the status file the CRI plugin keeps for each container.
// It has the exact start time and survives the task.
func (c *collector) criStatus(r *cdRoot, ct *report.Container) {
	p := joinLogical(r.root, cdCRIContainer, ct.ID, "status")
	data, err := c.readFile(p, 1<<20)
	if err != nil {
		if !isNotExist(err) {
			r.src.fail("CRI status", p, err)
		}
		return
	}
	var st struct {
		StartedAt  int64
		FinishedAt int64
	}
	if err := json.Unmarshal(data, &st); err != nil {
		r.src.fail("CRI status", p, err)
		return
	}
	if st.StartedAt > 0 {
		ct.StartedAt = time.Unix(0, st.StartedAt).UTC()
	}
	if st.FinishedAt > 0 {
		ct.Running = false
		ct.InitPID = 0
	}
}

// snapshotUpper maps a snapshot to the directory that holds its writable
// layer. Only the overlayfs snapshotter is understood.
func (c *collector) snapshotUpper(r *cdRoot, snapshotter, name string) string {
	if snapshotter != "overlayfs" {
		return ""
	}
	if r.snapIDs == nil {
		r.snapIDs = map[string]map[string]string{}
	}
	ids, ok := r.snapIDs[snapshotter]
	if !ok {
		p := joinLogical(r.root, cdSnapshotter+snapshotter, "metadata.db")
		var err error
		ids, err = c.readSnapshotIDs(p)
		if err != nil && !isNotExist(err) {
			r.src.fail("snapshotter database", p, err)
		}
		r.snapIDs[snapshotter] = ids
	}
	id := ids[name]
	if id == "" {
		return ""
	}
	return joinLogical(r.root, cdSnapshotter+snapshotter, "snapshots", id, "fs")
}

// readSnapshotIDs reads v1/snapshots/<name>/id (uvarint) from a snapshotter
// database.
func (c *collector) readSnapshotIDs(logical string) (map[string]string, error) {
	db, err := openBoltCopy(c.env.Path(logical))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	ids := map[string]string{}
	err = boltView(db, func(tx *bolt.Tx) error {
		b := bucketPath(tx, "v1", "snapshots")
		if b == nil {
			return nil
		}
		return b.ForEachBucket(func(k []byte) error {
			if id, n := binary.Uvarint(b.Bucket(k).Get([]byte("id"))); n > 0 {
				ids[string(k)] = strconv.FormatUint(id, 10)
			}
			return nil
		})
	})
	return ids, err
}

// containerdTasks lists running tasks when the metadata database cannot be
// read. Names and image references come from the OCI spec annotations; image
// digests are unknown.
func (c *collector) containerdTasks(r *cdRoot) {
	base := joinLogical(r.state, cdTasks)
	nss, err := c.readDir(base)
	if err != nil {
		if !isNotExist(err) {
			r.src.fail("task directory", base, err)
		} else {
			r.src.read = r.src.read || len(r.src.problems) == 0
		}
		return
	}
	r.src.read = true
	for _, ns := range nss {
		if !ns.IsDir() || ns.Name() == dockerNamespace {
			continue
		}
		nsDir := joinLogical(base, ns.Name())
		ids, err := c.readDir(nsDir)
		if err != nil {
			r.src.fail("task directory", nsDir, err)
			continue
		}
		for _, id := range ids {
			if c.done() {
				return
			}
			if !id.IsDir() || !safeName(id.Name()) {
				continue
			}
			c.taskFromSpec(r, ns.Name(), id.Name())
		}
	}
}

func (c *collector) taskFromSpec(r *cdRoot, ns, id string) {
	p := joinLogical(r.state, cdTasks, ns, id, "config.json")
	data, err := c.readFile(p, maxStateFile)
	if err != nil {
		r.src.fail("task spec", p, err)
		return
	}
	var spec struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		r.src.fail("task spec", p, err)
		return
	}
	a := spec.Annotations
	if a[annContainerType] == "sandbox" {
		return
	}
	ct := report.Container{ID: id, Runtime: RuntimeContainerd, Name: id}
	if a[annContainerName] != "" && a[annSandboxName] != "" {
		ct.Name = a[annSandboxNS] + "/" + a[annSandboxName] + "/" + a[annContainerName]
	} else if n := a[labelNerdctlName]; n != "" {
		ct.Name = n
	}
	if ref := a[annImageName]; ref != "" {
		ct.ImageRef = normalizeRef(ref)
	}
	c.taskState(r, ns, &ct)
	c.criStatus(r, &ct)
	if ct.Running {
		ct.UpperDir = c.upperFromMountinfo(ct.InitPID)
	}
	c.containers = append(c.containers, ct)
}

// ── content store ───────────────────────────────────────────────────────

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform,omitempty"`
}

type ociBlob struct {
	Manifests []ociDescriptor `json:"manifests"`
	Config    *ociDescriptor  `json:"config"`
	Layers    []ociDescriptor `json:"layers"`
}

// imageDetails follows an image target through the content store to its
// config. For an index it picks the host platform when its manifest is
// present, else the first platform that is. The size is what containerd and
// crictl report: the index, manifest, config and compressed layer blobs.
func (c *collector) imageDetails(r *cdRoot, target string) imageDetails {
	if d, ok := r.platforms[target]; ok {
		return d
	}
	if r.platforms == nil {
		r.platforms = map[string]imageDetails{}
	}
	var d imageDetails
	digest := target
	for range 3 { // index → (nested index) → manifest
		data, err := c.readBlob(r, digest)
		if err != nil {
			break
		}
		var blob ociBlob
		if json.Unmarshal(data, &blob) != nil {
			break
		}
		d.size += int64(len(data))
		if blob.Config != nil {
			d.size += blob.Config.Size
			for _, l := range blob.Layers {
				d.size += l.Size
			}
			if cfg, err := c.readBlob(r, blob.Config.Digest); err == nil {
				var ic struct {
					OS           string `json:"os"`
					Architecture string `json:"architecture"`
				}
				if json.Unmarshal(cfg, &ic) == nil {
					d.os, d.arch = ic.OS, ic.Architecture
				}
			}
			break
		}
		next := c.pickManifest(r, blob.Manifests)
		if next == "" {
			break
		}
		digest = next
	}
	r.platforms[target] = d
	return d
}

func (c *collector) pickManifest(r *cdRoot, list []ociDescriptor) string {
	first := ""
	for _, m := range list {
		if !c.usableManifest(r, m) {
			continue
		}
		if m.Platform != nil && m.Platform.OS == "linux" && m.Platform.Architecture == runtime.GOARCH {
			return m.Digest
		}
		if first == "" {
			first = m.Digest
		}
	}
	return first
}

// usableManifest skips invalid digests, attestation manifests and the
// platforms that were not pulled.
func (c *collector) usableManifest(r *cdRoot, m ociDescriptor) bool {
	if !validDigest(m.Digest) {
		return false
	}
	if m.Platform != nil && (m.Platform.OS == "unknown" || m.Platform.Architecture == "unknown") {
		return false
	}
	return c.exists(c.blobPath(r, m.Digest))
}

// maxChainBlobs bounds the blobs read for the chain ids of one image target.
const maxChainBlobs = 64

// imageChains holds the top chain id of every platform of an image target
// whose config could be read.
type imageChains struct {
	tops     []string
	readable bool
}

// imageChains follows an image target to the config of every platform that
// is in the content store. All of them are taken, not only the host
// platform's: a container may run another platform, and an index may have
// several platforms pulled.
func (c *collector) imageChains(r *cdRoot, target string) imageChains {
	if ch, ok := r.chains[target]; ok {
		return ch
	}
	if r.chains == nil {
		r.chains = map[string]imageChains{}
	}
	var ch imageChains
	queue, reads := []string{target}, 0
	for range 3 { // index → (nested index) → manifest
		var next []string
		for _, d := range queue {
			if reads >= maxChainBlobs || c.done() {
				break
			}
			reads++
			data, err := c.readBlob(r, d)
			if err != nil {
				continue
			}
			var blob ociBlob
			if json.Unmarshal(data, &blob) != nil {
				continue
			}
			if blob.Config == nil {
				for _, m := range blob.Manifests {
					if c.usableManifest(r, m) {
						next = append(next, m.Digest)
					}
				}
				continue
			}
			reads++
			if top, ok := c.configChain(r, blob.Config.Digest); ok {
				ch.tops = append(ch.tops, top)
				ch.readable = true
			}
		}
		queue = next
	}
	r.chains[target] = ch
	return ch
}

// configChain returns the chain id of the top layer of an image config, ""
// for an image without layers.
func (c *collector) configChain(r *cdRoot, digest string) (string, bool) {
	data, err := c.readBlob(r, digest)
	if err != nil {
		return "", false
	}
	var cfg struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return "", false
	}
	if len(cfg.RootFS.DiffIDs) == 0 {
		return "", true
	}
	ids := chainIDs(cfg.RootFS.DiffIDs)
	if ids == nil {
		return "", false
	}
	return ids[len(ids)-1], true
}

func (c *collector) blobPath(r *cdRoot, digest string) string {
	alg, hex, _ := strings.Cut(digest, ":")
	return joinLogical(r.root, cdBlobs, alg, hex)
}

func (c *collector) readBlob(r *cdRoot, digest string) ([]byte, error) {
	if !validDigest(digest) {
		return nil, fmt.Errorf("invalid digest %q", digest)
	}
	p := c.blobPath(r, digest)
	data, err := c.readFile(p, maxStateFile)
	if err != nil && !isNotExist(err) {
		r.src.fail("content blob", p, err)
	}
	return data, err
}
