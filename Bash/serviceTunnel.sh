#!/usr/bin/env bash
set -euo pipefail

# ####################################################################### #
#                                                                         #
# tunnel.sh - SSH tunnel helper for SIEM (Kibana) and EDR (Velociraptor)  #
#                                                                         #
# ####################################################################### #
#
# Overview
# This script has been put together to simply the connections to remote
# resources. It works by connecting to the system running the resource, 
# then creating an SSH port forward to allow access via local systems.
#
#                                WARNING
#
# This script assumes you have correctly configured access via the config
# (~/.ssh/config) file for the users.
#
# Examples:
#   ./tunnel.sh --siem
#   ./tunnel.sh --edr
#   ./tunnel.sh --siem --background
#   ./tunnel.sh --siem --bind 127.0.0.1 --kibana-port 5601
#   ./tunnel.sh --edr --edr-host edr --velo-port 8889
#   ./tunnel.sh --status
#   ./tunnel.sh --stop --siem
#
# Notes:
# - Expects SSH host aliases like "siem" and "edr" to exist in ~/.ssh/config (recommended).
# - Default bind is 127.0.0.1 to avoid exposing services to your network.

SCRIPT_NAME="$(basename "$0")"

DEFAULT_SIEM_HOST="siem"
DEFAULT_EDR_HOST="edr"
DEFAULT_BIND_ADDR="127.0.0.1"

DEFAULT_KIBANA_LOCAL_PORT="5601"
DEFAULT_KIBANA_REMOTE_HOST="localhost"
DEFAULT_KIBANA_REMOTE_PORT="5601"

DEFAULT_VELO_LOCAL_PORT="8889"
DEFAULT_VELO_REMOTE_HOST="localhost"
DEFAULT_VELO_REMOTE_PORT="8889"

# Runtime options
DO_SIEM=0
DO_EDR=0
DO_STATUS=0
DO_STOP=0

SIEM_HOST="$DEFAULT_SIEM_HOST"
EDR_HOST="$DEFAULT_EDR_HOST"
BIND_ADDR="$DEFAULT_BIND_ADDR"

KIBANA_LOCAL_PORT="$DEFAULT_KIBANA_LOCAL_PORT"
KIBANA_REMOTE_HOST="$DEFAULT_KIBANA_REMOTE_HOST"
KIBANA_REMOTE_PORT="$DEFAULT_KIBANA_REMOTE_PORT"

VELO_LOCAL_PORT="$DEFAULT_VELO_LOCAL_PORT"
VELO_REMOTE_HOST="$DEFAULT_VELO_REMOTE_HOST"
VELO_REMOTE_PORT="$DEFAULT_VELO_REMOTE_PORT"

IDENTITY_FILE=""
SSH_CONFIG_FILE=""
EXTRA_SSH_OPTS=()

BACKGROUND=0
VERBOSE=0

usage() {
  cat <<'EOF'
SSH tunnel helper for SIEM (Kibana) and EDR (Velociraptor)

Usage:
  tunnel.sh [OPTIONS]

Primary actions:
  --siem                 Create tunnel for Kibana (default: local 5601 -> siem:localhost:5601)
  --edr                  Create tunnel for Velociraptor (default: local 8889 -> edr:localhost:8889)
  --status               Show whether local tunnel ports are listening
  --stop                 Best-effort stop: kill local ssh processes bound to the selected port(s)

Options:
  -h, --help             Show this help

  --siem-host HOST       SSH host/alias for SIEM (default: siem)
  --edr-host HOST        SSH host/alias for EDR  (default: edr)

  --bind ADDR            Local bind address (default: 127.0.0.1)
                          Use 0.0.0.0 only if you intentionally want LAN exposure.

  --kibana-port PORT     Local port for Kibana tunnel (default: 5601)
  --kibana-remote HOST:PORT  Remote target for Kibana (default: localhost:5601)

  --velo-port PORT       Local port for Velociraptor tunnel (default: 8889)
  --velo-remote HOST:PORT    Remote target for Velociraptor (default: localhost:8889)

  --identity FILE        SSH identity key (-i FILE)
  --ssh-config FILE      SSH config file (-F FILE)
  --ssh-opt OPT          Additional ssh option (repeatable), e.g. --ssh-opt "-o ServerAliveInterval=30"

  --background           Run ssh with -N in the background (-f). Useful for long-lived tunnels.
  -v, --verbose          Verbose output (also enables ssh -v)

Examples:
  tunnel.sh --siem
  tunnel.sh --edr --background
  tunnel.sh --siem --bind 127.0.0.1 --kibana-port 15601
  tunnel.sh --edr --velo-remote 127.0.0.1:8889
  tunnel.sh --status
  tunnel.sh --stop --siem
EOF
}

die() { echo "ERROR: $*" >&2; exit 1; }

parse_hostport() {
  # Input: "host:port" => prints "host port"
  local hp="$1"
  [[ "$hp" == *:* ]] || die "Expected HOST:PORT, got: $hp"
  local host="${hp%:*}"
  local port="${hp##*:}"
  [[ -n "$host" ]] || die "Empty host in: $hp"
  [[ "$port" =~ ^[0-9]+$ ]] || die "Invalid port in: $hp"
  echo "$host" "$port"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

is_listening() {
  # Returns 0 if listening on tcp port, else 1
  local port="$1"
  ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${port}$"
}

kill_tunnel_by_port() {
  # Best-effort: find local ssh processes that include "-L <bind>:<port>:"
  # and kill them.
  local bind="$1"
  local lport="$2"

  # pattern tries to match: -L 127.0.0.1:5601: or -L127.0.0.1:5601:
  local pat1="-L[[:space:]]*${bind}:${lport}:"
  local pat2="-L${bind}:${lport}:"

  local pids
  pids="$(pgrep -af "ssh" | awk -v p1="$pat1" -v p2="$pat2" '$0 ~ p1 || $0 ~ p2 {print $1}')"

  if [[ -z "${pids}" ]]; then
    echo "No ssh tunnel process found for ${bind}:${lport}"
    return 0
  fi

  echo "Killing tunnel process(es) for ${bind}:${lport}: ${pids}"
  kill ${pids} || true
}

build_ssh_base_cmd() {
  local -a cmd=(ssh)

  # Background / no remote command
  # -N: do not execute remote command (tunnel only)
  # -T: no pseudo-tty
  cmd+=(-N -T)

  if [[ "$BACKGROUND" -eq 1 ]]; then
    cmd+=(-f)
  fi

  if [[ "$VERBOSE" -eq 1 ]]; then
    cmd+=(-v)
  fi

  # Keepalive defaults that reduce "mystery disconnects"
  cmd+=(-o ExitOnForwardFailure=yes)
  cmd+=(-o ServerAliveInterval=30)
  cmd+=(-o ServerAliveCountMax=3)

  if [[ -n "$IDENTITY_FILE" ]]; then
    cmd+=(-i "$IDENTITY_FILE")
  fi

  if [[ -n "$SSH_CONFIG_FILE" ]]; then
    cmd+=(-F "$SSH_CONFIG_FILE")
  fi

  if [[ "${#EXTRA_SSH_OPTS[@]}" -gt 0 ]]; then
    cmd+=("${EXTRA_SSH_OPTS[@]}")
  fi

  printf '%s\0' "${cmd[@]}"
}

run_siem() {
  local lspec="${BIND_ADDR}:${KIBANA_LOCAL_PORT}:${KIBANA_REMOTE_HOST}:${KIBANA_REMOTE_PORT}"
  echo "Opening SIEM (Kibana) tunnel: ${lspec} via SSH host '${SIEM_HOST}'"
  local base
  base="$(build_ssh_base_cmd)"
  # shellcheck disable=SC2206
  local -a cmd=()
  while IFS= read -r -d '' x; do cmd+=("$x"); done <<<"$base"
  cmd+=(-L "$lspec" "$SIEM_HOST")
  "${cmd[@]}"
  if [[ "$BACKGROUND" -eq 0 ]]; then
    echo "Tunnel active (foreground). Press Ctrl+C to close."
  else
    echo "Tunnel started (background)."
  fi
}

run_edr() {
  local lspec="${BIND_ADDR}:${VELO_LOCAL_PORT}:${VELO_REMOTE_HOST}:${VELO_REMOTE_PORT}"
  echo "Opening EDR (Velociraptor) tunnel: ${lspec} via SSH host '${EDR_HOST}'"
  local base
  base="$(build_ssh_base_cmd)"
  # shellcheck disable=SC2206
  local -a cmd=()
  while IFS= read -r -d '' x; do cmd+=("$x"); done <<<"$base"
  cmd+=(-L "$lspec" "$EDR_HOST")
  "${cmd[@]}"
  if [[ "$BACKGROUND" -eq 0 ]]; then
    echo "Tunnel active (foreground). Press Ctrl+C to close."
  else
    echo "Tunnel started (background)."
  fi
}

show_status() {
  need_cmd ss
  echo "Tunnel status (listening):"
  printf "  Kibana  %s:%s  ->  %s:%s via %s : " "$BIND_ADDR" "$KIBANA_LOCAL_PORT" "$KIBANA_REMOTE_HOST" "$KIBANA_REMOTE_PORT" "$SIEM_HOST"
  if is_listening "$KIBANA_LOCAL_PORT"; then echo "LISTENING"; else echo "not listening"; fi

  printf "  Velo    %s:%s  ->  %s:%s via %s : " "$BIND_ADDR" "$VELO_LOCAL_PORT" "$VELO_REMOTE_HOST" "$VELO_REMOTE_PORT" "$EDR_HOST"
  if is_listening "$VELO_LOCAL_PORT"; then echo "LISTENING"; else echo "not listening"; fi
}

stop_tunnels() {
  # Only stop what was selected, unless neither selected (then stop both).
  local stop_any=0

  if [[ "$DO_SIEM" -eq 1 || ( "$DO_SIEM" -eq 0 && "$DO_EDR" -eq 0 ) ]]; then
    stop_any=1
    kill_tunnel_by_port "$BIND_ADDR" "$KIBANA_LOCAL_PORT"
  fi

  if [[ "$DO_EDR" -eq 1 || ( "$DO_SIEM" -eq 0 && "$DO_EDR" -eq 0 ) ]]; then
    stop_any=1
    kill_tunnel_by_port "$BIND_ADDR" "$VELO_LOCAL_PORT"
  fi

  [[ "$stop_any" -eq 1 ]] || die "Nothing selected to stop."
}

main() {
  if [[ $# -eq 0 ]]; then
    usage
    exit 1
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --siem) DO_SIEM=1; shift ;;
      --edr) DO_EDR=1; shift ;;
      --status) DO_STATUS=1; shift ;;
      --stop) DO_STOP=1; shift ;;

      --siem-host) SIEM_HOST="${2:-}"; [[ -n "$SIEM_HOST" ]] || die "Missing value for --siem-host"; shift 2 ;;
      --edr-host)  EDR_HOST="${2:-}";  [[ -n "$EDR_HOST"  ]] || die "Missing value for --edr-host";  shift 2 ;;

      --bind) BIND_ADDR="${2:-}"; [[ -n "$BIND_ADDR" ]] || die "Missing value for --bind"; shift 2 ;;

      --kibana-port)
        KIBANA_LOCAL_PORT="${2:-}"; [[ "$KIBANA_LOCAL_PORT" =~ ^[0-9]+$ ]] || die "Invalid --kibana-port"
        shift 2
        ;;
      --kibana-remote)
        read -r KIBANA_REMOTE_HOST KIBANA_REMOTE_PORT < <(parse_hostport "${2:-}")
        shift 2
        ;;
      --velo-port)
        VELO_LOCAL_PORT="${2:-}"; [[ "$VELO_LOCAL_PORT" =~ ^[0-9]+$ ]] || die "Invalid --velo-port"
        shift 2
        ;;
      --velo-remote)
        read -r VELO_REMOTE_HOST VELO_REMOTE_PORT < <(parse_hostport "${2:-}")
        shift 2
        ;;

      --identity) IDENTITY_FILE="${2:-}"; [[ -n "$IDENTITY_FILE" ]] || die "Missing value for --identity"; shift 2 ;;
      --ssh-config) SSH_CONFIG_FILE="${2:-}"; [[ -n "$SSH_CONFIG_FILE" ]] || die "Missing value for --ssh-config"; shift 2 ;;
      --ssh-opt) EXTRA_SSH_OPTS+=("$2"); shift 2 ;;

      --background) BACKGROUND=1; shift ;;
      -v|--verbose) VERBOSE=1; shift ;;

      *)
        die "Unknown argument: $1 (use -h for help)"
        ;;
    esac
  done

  # Safety: require ssh
  need_cmd ssh

  # Execute operations
  if [[ "$DO_STATUS" -eq 1 ]]; then
    show_status
  fi

  if [[ "$DO_STOP" -eq 1 ]]; then
    stop_tunnels
  fi

  # If status/stop only, exit
  if [[ "$DO_STATUS" -eq 1 || "$DO_STOP" -eq 1 ]]; then
    exit 0
  fi

  # Must select at least one tunnel action
  if [[ "$DO_SIEM" -eq 0 && "$DO_EDR" -eq 0 ]]; then
    die "No action selected. Use --siem and/or --edr, or --status/--stop."
  fi

  # If both requested in foreground, second will never run. Force background for multi.
  if [[ "$DO_SIEM" -eq 1 && "$DO_EDR" -eq 1 && "$BACKGROUND" -eq 0 ]]; then
    die "You requested both --siem and --edr in foreground. Use --background, or run them separately."
  fi

  if [[ "$DO_SIEM" -eq 1 ]]; then
    run_siem
  fi

  if [[ "$DO_EDR" -eq 1 ]]; then
    run_edr
  fi
}

main "$@"
