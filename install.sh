#!/bin/sh
# Corv Client installer for Linux and macOS.
#   curl -fsSL https://raw.githubusercontent.com/khalid-src/corv-client/main/install.sh | sh
#
# Downloads the right prebuilt binary from the latest GitHub release, verifies
# its SHA-256 checksum, and puts it on your PATH. Override the install dir with
# BINDIR=/somewhere.
set -e

repo="khalid-src/corv-client"
bindir="${BINDIR:-/usr/local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
	x86_64 | amd64) arch="amd64" ;;
	arm64 | aarch64) arch="arm64" ;;
	*) echo "corv: unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
	linux | darwin) ;;
	*) echo "corv: unsupported OS: $os (use the Windows installer)" >&2; exit 1 ;;
esac

asset="corv-${os}-${arch}"
base="https://github.com/${repo}/releases/latest/download"

tmp=$(mktemp)
sums=$(mktemp)
cleanup() { rm -f "$tmp" "$sums"; }
trap cleanup EXIT

echo "Downloading ${asset} ..."
curl -fsSL "${base}/${asset}" -o "$tmp"
curl -fsSL "${base}/SHA256SUMS" -o "$sums"

expected=$(grep "$asset" "$sums" | awk '{print $1}' | head -n1)
if [ -z "$expected" ]; then
	echo "corv: no checksum for ${asset} in SHA256SUMS; refusing to install" >&2
	exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
	actual=$(sha256sum "$tmp" | awk '{print $1}')
else
	actual=$(shasum -a 256 "$tmp" | awk '{print $1}')
fi
if [ "$expected" != "$actual" ]; then
	echo "corv: checksum mismatch for ${asset}; refusing to install" >&2
	exit 1
fi

chmod +x "$tmp"
if [ -w "$bindir" ]; then
	mv "$tmp" "${bindir}/corv"
else
	echo "Installing to ${bindir} (requires sudo) ..."
	sudo mv "$tmp" "${bindir}/corv"
fi
trap - EXIT
rm -f "$sums"

echo "Installed corv to ${bindir}/corv"
echo "Run: corv"
