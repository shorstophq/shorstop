#!/usr/bin/env bash
# Runs `shorstop scan` for action.yml and writes SARIF. Exits 0 on exit code 0
# or 1, so code scanning still gets the results when findings cross the
# fail-on threshold; action.yml fails the job afterwards. Exit code 2 (a
# usage or scanner error) fails here, since there's no report to upload.
#
# Environment: SHORSTOP_PATH, SHORSTOP_FAIL_ON, SHORSTOP_BASELINE,
# SHORSTOP_CONFIG, SHORSTOP_ARGS, SHORSTOP_SARIF (the action inputs), plus
# RUNNER_TEMP, GITHUB_OUTPUT and GITHUB_WORKSPACE (set by Actions).
set -euo pipefail

path=${SHORSTOP_PATH:-.}
sarif=${SHORSTOP_SARIF:-${RUNNER_TEMP:?}/shorstop.sarif}

cmd=(shorstop scan "$path" --format sarif --output "$sarif" --fail-on "${SHORSTOP_FAIL_ON:-none}")
[[ -n ${SHORSTOP_BASELINE:-} ]] && cmd+=(--baseline "$SHORSTOP_BASELINE")
[[ -n ${SHORSTOP_CONFIG:-} ]] && cmd+=(--config "$SHORSTOP_CONFIG")
if [[ -n ${SHORSTOP_ARGS:-} ]]; then
  read -r -a extra <<<"$SHORSTOP_ARGS"
  # Length check first: bash 3.2 (macOS) treats an empty array as unset under set -u.
  ((${#extra[@]})) && cmd+=("${extra[@]}")
fi

echo "+ ${cmd[*]}"
code=0
"${cmd[@]}" || code=$?
echo "exit-code=$code" >>"${GITHUB_OUTPUT:?}"
echo "sarif-file=$sarif" >>"$GITHUB_OUTPUT"
if ((code != 0 && code != 1)); then
  echo "::error title=ShorStop::scan failed (exit code $code)"
  exit "$code"
fi

# SARIF paths are relative to the scanned directory, but code scanning
# resolves them against the repository root. When a subdirectory was
# scanned, prefix it so each finding links to the right file.
rel=${path//\\//}
if [[ -n ${GITHUB_WORKSPACE:-} && $rel == "${GITHUB_WORKSPACE//\\//}"/* ]]; then
  rel=${rel#"${GITHUB_WORKSPACE//\\//}"/}
fi
while [[ $rel == ./* ]]; do rel=${rel#./}; done
rel=${rel%/}
[[ $rel == . ]] && rel=
if [[ -n $rel ]]; then
  if [[ $rel == /* || /$rel/ == */../* ]]; then
    echo "::warning title=ShorStop::'$path' is outside the repository; code scanning may not link findings to files"
  else
    tmp=$sarif.tmp
    # Every artifact location relative to %SRCROOT%, wherever it appears.
    jq --arg p "$rel/" '
      (.. | objects | select(.uriBaseId? == "%SRCROOT%" and (.uri | type) == "string") | .uri) |= ($p + .)
    ' "$sarif" >"$tmp" && mv "$tmp" "$sarif"
  fi
fi
