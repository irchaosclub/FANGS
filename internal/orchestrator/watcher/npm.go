// SPDX-License-Identifier: Apache-2.0
//
// Package watcher polls the npm registry for new releases of watched
// packages and auto-queues sandbox scans. Per D31, v1 supports the
// official npm registry only; alternate registries (Verdaccio,
// JFrog, etc) land later via a Registry interface.
package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Registry is the abstraction over an npm-compatible registry. Tests
// swap in a fake; production uses the npmRegistry pointed at
// registry.npmjs.org.
type Registry interface {
	// LatestVersion returns the metadata for the package's current
	// dist-tags.latest. Returns ErrPackageNotFound when the package
	// doesn't exist on the registry.
	LatestVersion(ctx context.Context, packageName string) (PackageVersion, error)

	// Resolve returns the metadata for a specific (packageName,
	// version) pair. Pass version="" for an alias to LatestVersion.
	// Returns ErrPackageNotFound when the package doesn't exist, or
	// ErrVersionNotFound when the package exists but the version
	// doesn't. Used to validate a scan submission BEFORE the runner
	// wastes a sandbox on a 404.
	Resolve(ctx context.Context, packageName, version string) (PackageVersion, error)
}

// PackageVersion is the subset of npm metadata the Watcher cares about.
type PackageVersion struct {
	Name        string
	Version     string
	TarballSHA  string
	Integrity   string
	PublishedAt time.Time
}

// ErrPackageNotFound — registry returned 404 for the package.
var ErrPackageNotFound = fmt.Errorf("watcher: package not found on registry")

// ErrVersionNotFound — package exists but the requested version doesn't.
var ErrVersionNotFound = fmt.Errorf("watcher: version not found for package")

// npmRegistry is the default Registry implementation talking to
// https://registry.npmjs.org.
type npmRegistry struct {
	baseURL string
	http    *http.Client
}

// NewNPMRegistry constructs the default registry client.
func NewNPMRegistry() Registry {
	return &npmRegistry{
		baseURL: "https://registry.npmjs.org",
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (r *npmRegistry) LatestVersion(ctx context.Context, packageName string) (PackageVersion, error) {
	return r.Resolve(ctx, packageName, "")
}

// Resolve fetches the package metadata and returns the entry for either
// `version` (when non-empty) or dist-tags.latest. The fetch is the
// same single HTTP call regardless; LatestVersion is just an alias for
// version="".
func (r *npmRegistry) Resolve(ctx context.Context, packageName, version string) (PackageVersion, error) {
	meta, err := r.fetchMetadata(ctx, packageName)
	if err != nil {
		return PackageVersion{}, err
	}
	target := version
	if target == "" {
		target = meta.DistTags.Latest
		if target == "" {
			return PackageVersion{}, fmt.Errorf("registry returned no dist-tags.latest for %q", packageName)
		}
	}
	vd, ok := meta.Versions[target]
	if !ok {
		return PackageVersion{}, fmt.Errorf("%w: %s@%s", ErrVersionNotFound, packageName, target)
	}
	v := PackageVersion{
		Name:       packageName,
		Version:    target,
		TarballSHA: vd.Dist.SHASum,
		Integrity:  vd.Dist.Integrity,
	}
	if ts, ok := meta.Time[target]; ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			v.PublishedAt = t
		}
	}
	return v, nil
}

// npmMetadata is the slice of the registry's response we actually use.
type npmMetadata struct {
	DistTags struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
	Versions map[string]struct {
		Dist struct {
			Tarball   string `json:"tarball"`
			SHASum    string `json:"shasum"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
	} `json:"versions"`
	Time map[string]string `json:"time"`
}

func (r *npmRegistry) fetchMetadata(ctx context.Context, packageName string) (npmMetadata, error) {
	url := r.baseURL + "/" + packageName
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return npmMetadata{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		return npmMetadata{}, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return npmMetadata{}, ErrPackageNotFound
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return npmMetadata{}, fmt.Errorf("registry %s returned %d: %s", url, resp.StatusCode, string(b))
	}
	var meta npmMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return npmMetadata{}, fmt.Errorf("decode metadata: %w", err)
	}
	return meta, nil
}
