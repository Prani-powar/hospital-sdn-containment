#!/usr/bin/env bash
# Use either Compose v2 or Ubuntu's docker-compose v1.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if docker compose version >/dev/null 2>&1; then
  compose=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  compose=(docker-compose)
else
  echo "Docker Compose missing. Run setup.sh on the target VM." >&2
  exit 1
fi
exec "${compose[@]}" -p hospital-sdn-lab -f "$here/compose.yaml" "$@"
