#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./run_tunnel.sh [port]
# Default port: 5000
PORT="${1:-5000}"

CF_BIN="/home/guzhuowei0407/web_project/cloudflared"
if [[ ! -x "${CF_BIN}" ]]; then
	echo "cloudflared not found or not executable at ${CF_BIN}" >&2
	echo "Please ensure it exists and is chmod +x" >&2
	exit 1
fi

echo "Starting Cloudflare Quick Tunnel for http://localhost:${PORT} ..."
echo "Keep this terminal open to keep the tunnel alive."
exec "${CF_BIN}" tunnel --no-autoupdate --url "http://localhost:${PORT}"


