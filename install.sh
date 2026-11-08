#!/bin/sh
# Installs the latest kanareika release (or KANAREIKA_VERSION=v0.5.0; 0.5 or newer) for this machine:
#
#   curl -fsSL https://raw.githubusercontent.com/mikekosulin/kanareika/main/install.sh | sh
#
# Downloads the archive for this OS and CPU from GitHub releases, checks it against the release's SHA256SUMS and
# puts `kanareika` into /usr/local/bin (with sudo when needed) or, without root, ~/.local/bin. KANAREIKA_BIN_DIR
# chooses another directory. Nothing else is touched; to remove it, delete the binary.
set -eu

repo="mikekosulin/kanareika"
say() { printf '%s\n' "$*" >&2; }
die() { say "kanareika install: $*"; exit 1; }

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported OS $(uname -s): download a binary from https://github.com/$repo/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) die "unsupported CPU $(uname -m)" ;;
esac

if command -v curl >/dev/null 2>&1; then
  get() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  get() { wget -qO- "$1"; }
else
  die "curl or wget is needed"
fi

version="${KANAREIKA_VERSION:-}"
if [ -z "$version" ]; then
  version="$(get "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "$version" ] || die "could not find the latest release"
fi
base="https://github.com/$repo/releases/download/$version"
name="kanareika-$os-$arch"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
say "kanareika $version for $os/$arch"
get "$base/SHA256SUMS" >"$tmp/SHA256SUMS" || die "no SHA256SUMS in $version"

file="$name.tar.xz"
get "$base/$file" >"$tmp/$file" || die "no $file in $version (archives start with 0.5)"

want="$(grep " $file\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
if command -v sha256sum >/dev/null 2>&1; then
  have="$(sha256sum "$tmp/$file" | cut -d' ' -f1)"
else
  have="$(shasum -a 256 "$tmp/$file" | cut -d' ' -f1)"
fi
[ -n "$want" ] && [ "$want" = "$have" ] || die "checksum mismatch for $file: not installing"

tar -xJf "$tmp/$file" -C "$tmp" kanareika || die "could not unpack $file (is xz installed?)"

dir="${KANAREIKA_BIN_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then
    dir=/usr/local/bin
  elif [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1 && [ -t 2 ]; then
    say "installing into /usr/local/bin (sudo)"
    sudo install -m 755 "$tmp/kanareika" /usr/local/bin/kanareika
    dir=/usr/local/bin
    installed=1
  else
    dir="$HOME/.local/bin"
  fi
fi
if [ -z "${installed:-}" ]; then
  mkdir -p "$dir"
  install -m 755 "$tmp/kanareika" "$dir/kanareika" 2>/dev/null || cp "$tmp/kanareika" "$dir/kanareika"
fi
say "installed: $dir/kanareika"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "note: $dir is not in PATH; add it, or run $dir/kanareika" ;;
esac
say ""
say "Next: run  kanareika  (terminal)  or  kanareika web  (browser). It walks you through the first scan."
