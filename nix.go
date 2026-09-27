package sshbox

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var validPkgName = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// BuildNixEnv realizes packages from nixpkgs into a merged buildEnv profile in /nix/store
// and returns the path to its bin directory.
func BuildNixEnv(packages []string) (string, error) {
	if len(packages) == 0 {
		return "", nil
	}

	// Validate and quote package names to prevent any expression injection
	var quotedPkgs []string
	for _, p := range packages {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !validPkgName.MatchString(p) {
			return "", fmt.Errorf("invalid package name %q: must contain only alphanumeric characters, dots, dashes, or underscores", p)
		}
		quotedPkgs = append(quotedPkgs, strconv.Quote(p))
	}
	if len(quotedPkgs) == 0 {
		return "", nil
	}

	nixBin, err := findNixBinary()
	if err != nil {
		return "", fmt.Errorf("packages configured (%v) but %w", packages, err)
	}

	log.Printf("Building nix environment for packages: %v ...", packages)

	expr := fmt.Sprintf(
		`let pkgs = if builtins ? getFlake then (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem} else import <nixpkgs> {}; in pkgs.buildEnv { name = "sshbox-env"; paths = map (name: pkgs.${name}) [ %s ]; }`,
		strings.Join(quotedPkgs, " "),
	)

	var cmd *exec.Cmd
	if filepath.Base(nixBin) == "nix" {
		cmd = exec.Command(
			nixBin,
			"--extra-experimental-features", "nix-command flakes",
			"build",
			"--no-link",
			"--print-out-paths",
			"--impure",
			"--expr", expr,
		)
	} else {
		cmd = exec.Command(
			nixBin,
			"--no-out-link",
			"-E", expr,
		)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("nix build failed: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}

	storePath := strings.TrimSpace(string(out))
	if storePath == "" {
		return "", fmt.Errorf("nix build returned empty output")
	}

	binPath := filepath.Join(storePath, "bin")
	if fi, err := os.Stat(binPath); err == nil && fi.IsDir() {
		return binPath, nil
	}

	return storePath, nil
}

func findNixBinary() (string, error) {
	if p, err := exec.LookPath("nix"); err == nil {
		return p, nil
	}
	if p, err := exec.LookPath("nix-build"); err == nil {
		return p, nil
	}
	for _, p := range []string{
		"/run/current-system/sw/bin/nix",
		"/nix/var/nix/profiles/default/bin/nix",
		"/bin/nix",
		"/usr/bin/nix",
	} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("neither 'nix' nor 'nix-build' found in PATH")
}
