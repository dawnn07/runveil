#!/bin/sh
# runveil installer — downloads the latest release binary for your
# platform, verifies its SHA-256 checksum, and installs it onto your PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/dawnn07/runveil/main/install.sh | sh
#
# Environment:
#   RUNVEIL_VERSION      pin a release tag (e.g. v0.1.0); default: latest
#   RUNVEIL_INSTALL_DIR  install location; default: /usr/local/bin if
#                        writable, else $HOME/.local/bin
set -eu

REPO="dawnn07/runveil"
GITHUB="https://github.com"

err() { printf 'runveil install: %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }

# resolve_latest_tag follows the /releases/latest redirect and prints the
# tag (e.g. v0.1.0). Returns non-zero if it cannot be determined.
resolve_latest_tag() {
	url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$GITHUB/$REPO/releases/latest" 2>/dev/null) || return 1
	case "$url" in
		*/releases/tag/*) printf '%s\n' "${url##*/tag/}" ;;
		*) return 1 ;;
	esac
}

# install_dir prints the target directory per the documented precedence.
install_dir() {
	if [ "${RUNVEIL_INSTALL_DIR:-}" != "" ]; then
		printf '%s\n' "$RUNVEIL_INSTALL_DIR"
	elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
		printf '%s\n' /usr/local/bin
	else
		printf '%s\n' "$HOME/.local/bin"
	fi
}

main() {
	need curl
	need tar
	if command -v sha256sum >/dev/null 2>&1; then
		shacmd="sha256sum"
	elif command -v shasum >/dev/null 2>&1; then
		shacmd="shasum -a 256"
	else
		die "need sha256sum or shasum to verify the download"
	fi

	os=$(uname -s)
	case "$os" in
		Linux) os="linux" ;;
		Darwin) os="darwin" ;;
		*) die "unsupported OS '$os'; download the .zip from $GITHUB/$REPO/releases" ;;
	esac

	arch=$(uname -m)
	case "$arch" in
		x86_64|amd64) arch="amd64" ;;
		aarch64|arm64) arch="arm64" ;;
		*) die "unsupported architecture '$arch'" ;;
	esac

	if [ "${RUNVEIL_VERSION:-}" != "" ]; then
		tag="$RUNVEIL_VERSION"
	else
		tag=$(resolve_latest_tag) || die "could not determine the latest release tag (set RUNVEIL_VERSION to pin one)"
	fi

	asset="runveil_${tag}_${os}_${arch}.tar.gz"
	base="$GITHUB/$REPO/releases/download/$tag"

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT

	err "downloading $asset ($tag)…"
	curl -fsSL "$base/$asset" -o "$tmp/$asset" || die "download failed: $base/$asset"
	curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"

	( cd "$tmp" && grep " $asset\$" SHA256SUMS > SHA256SUMS.one ) || die "no checksum listed for $asset"
	( cd "$tmp" && $shacmd -c SHA256SUMS.one >/dev/null 2>&1 ) || die "checksum verification failed for $asset"

	tar -xzf "$tmp/$asset" -C "$tmp" runveil || die "could not extract runveil from $asset"

	dir=$(install_dir)
	mkdir -p "$dir" || die "cannot create install dir: $dir"
	if ! install -m 0755 "$tmp/runveil" "$dir/runveil" 2>/dev/null; then
		cp "$tmp/runveil" "$dir/runveil" || die "could not install to $dir"
		chmod 0755 "$dir/runveil" || die "could not set permissions on $dir/runveil"
	fi

	err "installed runveil $tag to $dir/runveil"
	case ":$PATH:" in
		*":$dir:"*) ;;
		*) err "note: $dir is not on your PATH; add it, e.g. export PATH=\"$dir:\$PATH\"" ;;
	esac
	err "next: run 'runveil init' to set up the local CA and starter policy"
}

main "$@"
