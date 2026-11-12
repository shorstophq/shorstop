#!/usr/bin/env bash
# Installs a ShorStop release binary for the GitHub Actions runner (used by
# action.yml). Downloads the archive for this runner's OS and architecture,
# checks it against checksums.txt and, unless SHORSTOP_VERIFY=false, verifies
# checksums.txt's keyless cosign signature first, so a tampered or swapped
# download is rejected. Puts `shorstop` on PATH for the following steps.
#
# Environment:
#   SHORSTOP_VERSION         latest (newest full release) or a tag, e.g. v0.1.0
#   SHORSTOP_VERIFY          true (default) or false
#   SHORSTOP_DOWNLOAD_BASE   release download URL (override for local tests)
#   RUNNER_OS, RUNNER_ARCH, RUNNER_TEMP, GITHUB_PATH, GITHUB_OUTPUT (set by Actions)
set -euo pipefail

repo_url=https://github.com/shorstophq/shorstop
base=${SHORSTOP_DOWNLOAD_BASE:-$repo_url/releases/download}
version=${SHORSTOP_VERSION:-latest}
verify=${SHORSTOP_VERIFY:-true}

fail() { echo "::error title=ShorStop install::$*"; exit 1; }

case "${RUNNER_OS:-}" in
  Linux) os=linux ext=tar.gz ;;
  macOS) os=darwin ext=tar.gz ;;
  Windows) os=windows ext=zip ;;
  *) fail "unsupported runner OS '${RUNNER_OS:-}'" ;;
esac
case "${RUNNER_ARCH:-}" in
  X64) arch=amd64 ;;
  ARM64) arch=arm64 ;;
  *) fail "unsupported runner architecture '${RUNNER_ARCH:-}'" ;;
esac
[[ $os/$arch == windows/arm64 ]] && fail "no Windows on ARM build yet; use an x64 Windows runner"

# "latest" follows GitHub's redirect from /releases/latest to /releases/tag/<tag>.
# No API call, so no rate limit. GitHub never counts a pre-release as "latest".
if [[ $version == latest ]]; then
  url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' --retry 3 "$repo_url/releases/latest") ||
    fail "couldn't find the latest release"
  tag=${url##*/tag/}
  [[ $url == */tag/* && -n $tag ]] ||
    fail "no full release found; set 'version' (for a pre-release, e.g. v0.1.0-rc.1)"
else
  tag=v${version#v} # accept 0.1.0 or v0.1.0
fi
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail "'$tag' isn't a release version like v0.1.0"

archive=shorstop_${tag#v}_${os}_${arch}.$ext
dir=${RUNNER_TEMP:?}/shorstop-$tag
mkdir -p "$dir"
cd "$dir"

echo "Installing ShorStop $tag ($os/$arch)"
download() { curl -fsSL --retry 3 -o "$1" "$base/$tag/$1" || fail "download failed: $base/$tag/$1"; }
download checksums.txt
download "$archive"

if [[ $verify == true ]]; then
  command -v cosign >/dev/null || fail "cosign not found (set verify: false to skip signature verification)"
  download checksums.txt.sigstore.json
  # Exact identity: signed by this repository's release workflow, for this tag.
  cosign verify-blob \
    --bundle checksums.txt.sigstore.json \
    --certificate-identity "$repo_url/.github/workflows/release.yml@refs/tags/$tag" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    checksums.txt || fail "checksums.txt signature verification failed"
else
  echo "::warning title=ShorStop install::signature verification skipped (verify: false)"
fi

line=$(grep -E "^[0-9a-f]{64}  $archive\$" checksums.txt) || fail "$archive isn't listed in checksums.txt"
if command -v sha256sum >/dev/null; then
  sha256sum -c - <<<"$line" >/dev/null
else
  shasum -a 256 -c - <<<"$line" >/dev/null # macOS
fi || fail "$archive doesn't match checksums.txt"

if [[ $ext == zip ]]; then
  # Git Bash's tar can't read zip; PowerShell can.
  pwsh -NoProfile -Command "Expand-Archive -Force -Path '$archive' -DestinationPath '.'"
  bin=shorstop.exe
else
  tar -xzf "$archive"
  bin=shorstop
fi
[[ -f $bin ]] || fail "$bin missing from $archive"

echo "$dir" >>"${GITHUB_PATH:?}"
echo "version=$tag" >>"${GITHUB_OUTPUT:?}"
"./$bin" version
