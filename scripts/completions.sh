#!/bin/sh
# Writes shell completion scripts into completions/ for the release archives
# (run by GoReleaser's before hook). They're generated at release time, not
# at install time: Homebrew would have to run the binary, which macOS
# blocks while the download is still quarantined.
set -eu
rm -rf completions
mkdir completions
for shell in bash zsh fish; do
  go run ./cmd/shorstop completion "$shell" >"completions/shorstop.$shell"
done
