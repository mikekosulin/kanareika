#!/bin/sh
# Installs the latest kanareika release (or KANAREIKA_VERSION=v0.5.0; 0.5 or newer) for this machine. Read it first,
# then run it:
#
#   curl -fsSLO https://raw.githubusercontent.com/mikekosulin/kanareika/main/install.sh
#   less install.sh
#   sh install.sh
#
# What it does: downloads kanareika-<os>-<arch>.tar.xz from the GitHub release, checks it against the release's
# SHA256SUMS (and its build attestation when the GitHub CLI `gh` is installed), asks before installing, and puts
# `kanareika` into /usr/local/bin (with sudo when needed) or, without root, ~/.local/bin. Nothing else is touched;
# to remove it, delete that one file.
#
#   KANAREIKA_BIN_DIR=<DIR>   install there instead
#   KANAREIKA_YES=1           don't ask (scripts, CI)
#
# Everything runs from main() on the last line: a download cut short executes nothing.
set -eu

repo="mikekosulin/kanareika"
say() { printf '%s\n' "$*" >&2; }
die() {
  say "kanareika install: $*"
  exit 1
}

main() {
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
  file="kanareika-$os-$arch.tar.xz"

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT INT TERM
  say "kanareika $version for $os/$arch"
  get "$base/SHA256SUMS" >"$tmp/SHA256SUMS" || die "no SHA256SUMS in $version"
  get "$base/$file" >"$tmp/$file" || die "no $file in $version (archives start with 0.5)"

  want="$(grep " $file\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
  if command -v sha256sum >/dev/null 2>&1; then
    have="$(sha256sum "$tmp/$file" | cut -d' ' -f1)"
  else
    have="$(shasum -a 256 "$tmp/$file" | cut -d' ' -f1)"
  fi
  [ -n "$want" ] && [ "$want" = "$have" ] || die "checksum mismatch for $file: not installing"
  say "checksum: ok"
  if command -v gh >/dev/null 2>&1; then
    gh attestation verify "$tmp/$file" --repo "$repo" >/dev/null 2>&1 ||
      die "the build attestation of $file does not verify: not installing"
    say "build attestation: ok (built by $repo's release workflow)"
  fi

  tar -xJf "$tmp/$file" -C "$tmp" kanareika || die "could not unpack $file (is xz installed?)"

  dir="${KANAREIKA_BIN_DIR:-}"
  sudo=""
  if [ -z "$dir" ]; then
    if [ -w /usr/local/bin ]; then
      dir=/usr/local/bin
    elif [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1 && [ -r /dev/tty ]; then
      dir=/usr/local/bin sudo=sudo
    else
      dir="$HOME/.local/bin"
    fi
  fi

  if [ "${KANAREIKA_YES:-}" != 1 ] && [ -r /dev/tty ]; then
    printf 'Install kanareika %s into %s%s? [Y/n] ' "$version" "$dir" "${sudo:+ (with sudo)}" >&2
    read -r answer </dev/tty || answer=n
    case "$answer" in
      "" | y | Y | yes | YES) ;;
      *) die "not installed" ;;
    esac
  fi

  $sudo mkdir -p "$dir"
  $sudo install -m 755 "$tmp/kanareika" "$dir/kanareika"
  say "installed: $dir/kanareika"
  case ":$PATH:" in
    *":$dir:"*) ;;
    *) say "note: $dir is not in PATH; add it, or run $dir/kanareika" ;;
  esac
  say ""
  say "Next: run  kanareika  (terminal)  or  kanareika web  (browser). It walks you through the first scan."
}

main "$@"
