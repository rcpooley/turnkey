#!/usr/bin/env bash
# A throwaway Dolt sql-server for the test suite: scripts/test-dolt.sh start|stop.
# Port TURNKEY_DOLT_PORT (default 3518); data under .dev/dolt (gitignored).
set -euo pipefail
cd "$(dirname "$0")/.."
DOLT="${DOLT_BIN:-$(command -v dolt || echo "$HOME/bin/dolt")}"
PORT="${TURNKEY_DOLT_PORT:-3518}"
DIR="$PWD/.dev/dolt"; PID="$DIR/.pid"
case "${1:-}" in
  start)
    if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then echo "running on 127.0.0.1:$PORT"; exit 0; fi
    rm -rf "$DIR"; mkdir -p "$DIR"
    cat > "$DIR/config.yaml" <<YAML
log_level: warning
behavior: {read_only: false, autocommit: true}
user: {name: root, password: ""}
listener: {host: 127.0.0.1, port: $PORT, max_connections: 200}
data_dir: .
YAML
    ( cd "$DIR" && exec nohup "$DOLT" sql-server --config config.yaml >server.log 2>&1 ) </dev/null &
    echo $! > "$PID"
    for _ in $(seq 1 80); do
      node -e "require('net').connect($PORT,'127.0.0.1').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))" && { echo "dolt up on 127.0.0.1:$PORT"; exit 0; }
      sleep 0.25
    done
    echo "dolt did not start; see $DIR/server.log" >&2; exit 1 ;;
  stop)
    if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then kill "$(cat "$PID")"; fi
    rm -f "$PID" ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
