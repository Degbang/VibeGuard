#!/usr/bin/env bash
# Scan any Java project with VibeGuard via Docker - no local Python/venv
# setup needed. Builds the image on first use (and whenever the source
# changes, since Docker caches by layer), then runs the scan.
#
# Usage:
#   scripts/scan.sh <path-to-project> [extra vibeguard args...]
#
# Examples:
#   scripts/scan.sh ~/code/some-java-service
#   scripts/scan.sh ~/code/some-java-service --timeout 10
#   scripts/scan.sh ./pom.xml
#
# The target path is mounted read-only - the scanner never needs, and is
# never given, write access to the project it's scanning.

set -euo pipefail

IMAGE_NAME="vibeguard"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <path-to-project-to-scan> [extra vibeguard args...]" >&2
  echo "  e.g. $0 ~/code/some-java-service" >&2
  exit 2
fi

TARGET_PATH="$1"
shift

if [[ ! -e "$TARGET_PATH" ]]; then
  echo "error: $TARGET_PATH does not exist" >&2
  exit 2
fi

# Resolve to an absolute path - Docker's -v needs one, and this also
# matches main.py's own path-resolution behavior for a single-file target.
RESOLVED_TARGET="$(cd "$(dirname "$TARGET_PATH")" && pwd)/$(basename "$TARGET_PATH")"

docker build -t "$IMAGE_NAME" "$REPO_ROOT" >&2

if [[ -d "$RESOLVED_TARGET" ]]; then
  MOUNT_SOURCE="$RESOLVED_TARGET"
  CONTAINER_TARGET="/scan-target"
else
  # A single file (e.g. a lone pom.xml): mount its parent directory and
  # point the scanner at the file's own name inside the container, since
  # Docker's -v always mounts a directory.
  MOUNT_SOURCE="$(dirname "$RESOLVED_TARGET")"
  CONTAINER_TARGET="/scan-target/$(basename "$RESOLVED_TARGET")"
fi

docker run --rm \
  -v "$MOUNT_SOURCE":/scan-target:ro \
  "$IMAGE_NAME" "$CONTAINER_TARGET" "$@"
