#!/bin/bash
# start_client_services.sh (client-lite, aligned with orchestration_cli.sh)

set -euo pipefail

# =========[ PATHS ]=========
ROOT_PATH="$(pwd)"
ROOT_PATH_PYTHON="$(dirname "$(pwd)")"
PYTHON_V_ENV="$ROOT_PATH_PYTHON/.venv/bin/python"

BLOCKCHAIN_SCRIPT="$ROOT_PATH/client_blockchain_init.py"
FLASK_SCRIPT="$ROOT_PATH/orchestration_service.py"       # exposes /acknowledgement
NODE_REGISTRATION_SCRIPT="$ROOT_PATH/orchestration_service.py"  # sends /register-node to root

# =========[ COLORS ]=========
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"; CYAN="\033[36m"; RESET="\033[0m"
hdr(){ echo -e "\n${BLUE}========== $1 ==========${RESET}"; }
ok(){ echo -e "${GREEN}[✔] $1${RESET}"; }
warn(){ echo -e "${YELLOW}[!] $1${RESET}"; }
err(){ echo -e "${RED}[✘] $1${RESET}"; }

# =========[ NET HELPERS ]=========
detect_ip(){
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 addr show wlan0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 || true)"
    [[ -z "$ip" ]] && ip="$(ip -4 addr show eth0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 || true)"
  fi
  [[ -z "$ip" && $(command -v hostname) ]] && ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [[ -z "$ip" ]] && ip="127.0.0.1"
  echo "$ip"
}
Naked_IP_ADD="$(detect_ip)"
IP_ADDRESS="http://${Naked_IP_ADD}"

# =========[ ENV ]=========
load_or_create_env(){
  if [[ -f "$ROOT_PATH/.env" ]]; then
    echo ".env found. Loading…"
    set -o allexport; # shellcheck disable=SC1091
    source "$ROOT_PATH/.env"
    set +o allexport
    : "${FLASK_PORT:=5001}"
    : "${BESU_PORT:=8546}"
    : "${P2P_PORT:=30304}"
    : "${NODE_URL:=${IP_ADDRESS}:$FLASK_PORT}"
    : "${BESU_RPC_URL:=${IP_ADDRESS}:$BESU_PORT}"
  else
    echo ".env not found. Creating…"
    read -rp "Enter FLASK_PORT [5001]: " FLASK_PORT_INPUT
    read -rp "Enter BESU_PORT  [8546]: " BESU_PORT_INPUT
    read -rp "Enter P2P_PORT   [30304]: " P2P_PORT_INPUT
    FLASK_PORT="${FLASK_PORT_INPUT:-5001}"
    BESU_PORT="${BESU_PORT_INPUT:-8546}"
    P2P_PORT="${P2P_PORT_INPUT:-30304}"
    NODE_URL="${IP_ADDRESS}:${FLASK_PORT}"
    BESU_RPC_URL="${IP_ADDRESS}:${BESU_PORT}"
    cat > "$ROOT_PATH/.env" <<EOF
FLASK_PORT=${FLASK_PORT}
BESU_PORT=${BESU_PORT}
P2P_PORT=${P2P_PORT}
NODE_URL=${NODE_URL}
BESU_RPC_URL=${BESU_RPC_URL}
EOF
    ok ".env created:"
    cat "$ROOT_PATH/.env"
  fi
}
load_or_create_env

# =========[ ACK FILES ]=========
GENESIS_PATH="$ROOT_PATH/genesis/genesis.json"
REGISTRY_PATH_A="$ROOT_PATH/smart_contract_deployment/build/contracts/NodeRegistry.json"
REGISTRY_PATH_B="$ROOT_PATH/data/NodeRegistry.json"
PREFUNDED_KEYS="$ROOT_PATH/prefunded_keys.json"
ENODE_FILE="$ROOT_PATH/static/enode.txt"
have_registry(){ [[ -s "$REGISTRY_PATH_A" || -s "$REGISTRY_PATH_B" ]]; }

# =========[ CORE ]=========
client_start_service() {
  hdr "Starting Orchestration API (Client)"
  if lsof -iTCP:"$FLASK_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    err "Flask is already running on port $FLASK_PORT"
    return 1
  fi
  # osascript -e "tell application \"Terminal\" to do script \"$PYTHON_V_ENV $FLASK_SCRIPT --host 0.0.0.0 --port $FLASK_PORT --repo-root $ROOT_PATH\""
  launch_cmd "$PYTHON_V_ENV $FLASK_SCRIPT --host 0.0.0.0 --port $FLASK_PORT --repo-root $ROOT_PATH"

  ok "API starting on $FLASK_PORT"
}

# =========[ LAUNCH HELPER ]=========
launch_cmd() {
  # $1 = command string to run
  if [[ "$OSTYPE" == "darwin"* ]] && command -v osascript >/dev/null 2>&1; then
    osascript -e "tell application \"Terminal\" to do script \"$1\""
  else
    nohup bash -lc "$1" >/dev/null 2>&1 &
    disown || true
  fi
}


init_chain_client(){
  hdr "Initializing client keys"
  if [[ -f "$ROOT_PATH/data/key.priv" && -f "$ROOT_PATH/data/key.pub" ]]; then
    warn "Keys already exist; skipping."
  else
    "$PYTHON_V_ENV" "$BLOCKCHAIN_SCRIPT" generate_keys
    "$PYTHON_V_ENV" "$BLOCKCHAIN_SCRIPT" generate_account 1
    ok "Keys generated."
  fi
}

# await_ack(){
#   local timeout="${1:-120}"
#   hdr "Waiting for ACK (<= ${timeout}s)"
#   local t=0
#   while (( t < timeout )); do
#     if [[ -s "$GENESIS_PATH" && -s "$PREFUNDED_KEYS" && -s "$ENODE_FILE" ]] && have_registry; then
#       ok "ACK received (genesis + NodeRegistry + prefunded_keys + enode)."
#       return 0
#     fi
#     sleep 2; ((t+=2))
#   done
#   err "ACK timeout. Expect files:"
#   echo " - $GENESIS_PATH"
#   echo " - $REGISTRY_PATH_A  (or $REGISTRY_PATH_B)"
#   echo " - $PREFUNDED_KEYS"
#   echo " - $ENODE_FILE"
#   return 1
# }

start_chain_client(){
  hdr "Starting Besu (client)"
  if ! [[ -s "$GENESIS_PATH" && -s "$PREFUNDED_KEYS" ]] || ! have_registry; then
    err "ACK not present. Run: $0 start-flask ; $0 register … ; $0 await-ack"
    exit 1
  fi

  # osascript -e "tell application \"Terminal\" to do script \"$PYTHON_V_ENV $BLOCKCHAIN_SCRIPT start_blockchain_node $P2P_PORT $BESU_PORT $Naked_IP_ADD\""
  launch_cmd "$PYTHON_V_ENV $BLOCKCHAIN_SCRIPT start_blockchain_node $P2P_PORT $BESU_PORT $Naked_IP_ADD"
  # ok "Besu starting (RPC $BESU_RPC_URL, P2P $P2P_PORT). Log: $ROOT_PATH/besu.log"

  sleep 2
  if pgrep -f "[b]esu" >/dev/null; then
    ok "Besu started (RPC $BESU_RPC_URL, P2P $P2P_PORT). Log: $ROOT_PATH/besu.log"
  else
    err "Besu failed. See $ROOT_PATH/besu.log"
    exit 1
  fi
}

stop_chain_client(){ hdr "Stopping Besu"; pkill -f "besu" && ok "Stopped" || warn "No besu process"; }
restart_chain_client(){ hdr "Restarting Besu"; stop_chain_client; sleep 2; start_chain_client; }

reinit_chain_client(){
  hdr "Reinitializing client (wipe state)"
  rm -rf "$ROOT_PATH/data" "$ROOT_PATH/genesis" "$ROOT_PATH/node-details.json" \
         "$ROOT_PATH/prefunded_keys.json" "$ROOT_PATH/.env" "$ROOT_PATH/static/enode.txt" "$ROOT_PATH/policy_index.json"
  ok "State wiped."
  load_or_create_env
  init_chain_client
}

register_node() {
  hdr "Registration (POST /register-node)"

  # Args: <node_id> <node_name> <node_type> <root_host:port> [wants_validator:true|false|auto]
  local node_id="${1:-}" node_name="${2:-}" node_type="${3:-}" root_hp="${4:-}" wants="${5:-auto}"
  if [[ -z "$node_id" || -z "$node_name" || -z "$node_type" || -z "$root_hp" ]]; then
    err "Usage: $0 register <node_id> <node_name> <node_type> <root_host:port> [wants_validator:true|false|auto]"
    return 1
  fi

  local registration_url="http://${root_hp}"         # root orchestration_service base
  local api_base="$registration_url"                 # alias for clarity
  local pub_path="$ROOT_PATH/data/key.pub"
  local priv_path="$ROOT_PATH/data/key.priv"
  local rpc_url="${BESU_RPC_URL:-${IP_ADDRESS}:${BESU_PORT}}"  # this client's RPC
  local wants_bool=false
  # if lsof -iTCP:"$FLASK_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  #   ok "Flask is already running on port $FLASK_PORT"
  # else
  #   warn "Flask not running; starting…"
  #   osascript -e "tell application \"Terminal\" to do script \"$PYTHON_V_ENV $FLASK_SCRIPT --host 0.0.0.0 --port $FLASK_PORT --repo-root $ROOT_PATH\""
  #   # Wait until /health responds (up to ~10s)
  #   for i in {1..20}; do
  #     sleep 0.5
  #     if curl -sf "http://127.0.0.1:${FLASK_PORT}/health" >/dev/null 2>&1; then
  #       ok "Flask is up on $FLASK_PORT"
  #       break
  #     fi
  #   done
  #   if ! curl -sf "http://127.0.0.1:${FLASK_PORT}/health" >/dev/null 2>&1; then
  #     err "Failed to start Flask on $FLASK_PORT"
  #     return 1
  #   fi
  # fi
  echo "ID: $node_id"
  echo "Name: $node_name"
  echo "Type: $node_type"
  echo "Root API: $registration_url"
  echo "Node URL (callback): $NODE_URL"
  echo "RPC URL: $rpc_url"

  # Require both keys; bundle needs them and also writes node-details.json
  if [[ ! -f "$pub_path" || ! -f "$priv_path" ]]; then
    err "Missing $pub_path or $priv_path. Run: $0 init-chain-client"
    return 1
  fi

  # Resolve wants_validator if "auto"
  if [[ "$wants" == "auto" ]]; then
    wants_bool=false
    case "$node_type" in
      Cloud|Fog) wants_bool=true ;;
    esac
    # If this address is already a validator (as seen by root), force true
    if curl -fsS "$api_base/validators" >/dev/null 2>&1; then
      my_addr="$("$PYTHON_V_ENV" "$ROOT_PATH/node_identity.py" address "$priv_path" 2>/dev/null || true)"
      if [[ -n "$my_addr" ]] && curl -fsS "$api_base/validators" | grep -qi "$(echo "$my_addr" | tr '[:upper:]' '[:lower:]')" ; then
        wants_bool=true
      fi
    fi
  else
    wants_bool=$( [[ "$wants" == "true" ]] && echo true || echo false )
  fi

  # Build identity bundle JSON (this also writes/updates node-details.json)
  local bundle_json
  if ! bundle_json="$("$PYTHON_V_ENV" "$ROOT_PATH/node_identity.py" bundle \
      "$node_id" "$node_name" "$node_type" "$pub_path" "$priv_path" "$rpc_url" "$NODE_URL" "$wants_bool")"; then
    err "Failed to build identity bundle"
    return 1
  fi

  echo "POST -> $api_base/register-node"
  if command -v jq >/dev/null 2>&1; then echo "$bundle_json" | jq .; else echo "$bundle_json"; fi

  # Send registration to root
  curl -s -X POST "$api_base/register-node" \
    -H "Content-Type: application/json" \
    -d "$bundle_json" | (command -v jq >/dev/null 2>&1 && jq . || cat)

  ok "Registration sent. node-details.json updated. Root will ACK for Fog/Edge only."
}

status(){
  hdr "Client Status"
  echo "IP:            $Naked_IP_ADD"
  echo "NODE_URL:      $NODE_URL"
  echo "BESU_RPC_URL:  $BESU_RPC_URL"
  echo "FLASK_PORT:    $FLASK_PORT"
  echo "BESU_PORT:     $BESU_PORT"
  echo "P2P_PORT:      $P2P_PORT"
  echo
  echo "ACK files:"
  [[ -s "$GENESIS_PATH" ]] && echo " - genesis: OK" || echo " - genesis: MISSING"
  if have_registry; then echo " - NodeRegistry.json: OK"; else echo " - NodeRegistry.json: MISSING"; fi
  [[ -s "$PREFUNDED_KEYS" ]] && echo " - prefunded_keys.json: OK" || echo " - prefunded_keys.json: MISSING"
  [[ -s "$ENODE_FILE" ]] && echo " - enode.txt: OK ($(head -c 80 "$ENODE_FILE" 2>/dev/null; echo "..."))" || echo " - enode.txt: MISSING"
  echo
  if pgrep -f "[b]esu" >/dev/null; then ok "Besu is running"; else warn "Besu not running"; fi
}

# ===== Unified access helpers (root/client) =====

# --- compatibility wrappers so this block works in both scripts ---
_header() {
  if declare -F print_header >/dev/null 2>&1; then print_header "$1";
  elif declare -F hdr >/dev/null 2>&1; then hdr "$1";
  else echo -e "\n========== $1 =========="; fi
}
_err() {
  if declare -F error >/dev/null 2>&1; then error "$1";
  elif declare -F err >/dev/null 2>&1; then err "$1";
  else echo "ERROR: $1" >&2; fi
}

# POST /access (generic)
# Usage: client-access <root_host:port> <from_sig> <METHOD> </resource_path> [expiry_secs] [allow_delegation(true|false)] [delegation_depth]
client_access() {
  local root_hp="$1" from_sig="$2" method="$3" path="$4" expiry="${5:-900}" allow="${6:-false}" depth="${7:-0}"
  if [ -z "$root_hp" ] || [ -z "$from_sig" ] || [ -z "$method" ] || [ -z "$path" ]; then
    _err "Usage: $0 client-access <root_host:port> <from_sig> <METHOD> </resource_path> [expiry_secs] [allow_delegation(true|false)] [delegation_depth]"
    exit 1
  fi
  local API="http://$root_hp"
  _header "Client → POST $API/access ($method $path)"

  curl -s -X POST "$root_hp/access" -H "Content-Type: application/json" \
    -d "{\"from_signature\":\"$from_sig\",\"method\":\"$method\",\"resource_path\":\"$path\",\"expiry_secs\":$expiry,\"allow_delegation\":$allow,\"delegation_depth\":$depth}" \
    | (command -v jq >/dev/null 2>&1 && jq . || cat)
}

# ----- Convenience endpoints (receiver derives to_signature itself) -----

# GET /temperature
# Usage: temp-read <root_host:port> <from_sig> [/resource_path]
temp_read() {
  local root_hp="$1" from_sig="$2" path="${3:-/temperature}"
  if [ -z "$root_hp" ] || [ -z "$from_sig" ]; then
    _err "Usage: $0 temp-read <root_host:port> <from_sig> [/resource_path]"
    exit 1
  fi
  local API="http://$root_hp"
  _header "Client → GET $API$path"
  curl -s -X GET "$API/temperature?from_signature=$from_sig&resource_path=$path" \
    | (command -v jq >/dev/null 2>&1 && jq . || cat)
}

# POST /temperature
# Usage: temp-write <root_host:port> <from_sig> [/resource_path]
temp_write() {
  local root_hp="$1" from_sig="$2" path="${3:-/temperature}"
  if [ -z "$root_hp" ] || [ -z "$from_sig" ]; then
    _err "Usage: $0 temp-write <root_host:port> <from_sig> [/resource_path]"
    exit 1
  fi
  local API="http://$root_hp"
  _header "Client → POST $API$path"
  curl -s -X POST "$API/temperature?from_signature=$from_sig&resource_path=$path" \
    | (command -v jq >/dev/null 2>&1 && jq . || cat)
}

# PUT /firmware
# Usage: fw-update <root_host:port> <from_sig> [/resource_path]
fw_update() {
  local root_hp="$1" from_sig="$2" path="${3:-/firmware}"
  if [ -z "$root_hp" ] || [ -z "$from_sig" ]; then
    _err "Usage: $0 fw-update <root_host:port> <from_sig> [/resource_path]"
    exit 1
  fi
  local API="http://$root_hp"
  _header "Client → PUT $API$path"
  curl -s -X PUT "$API/firmware?from_signature=$from_sig&resource_path=$path" \
    | (command -v jq >/dev/null 2>&1 && jq . || cat)
}

# DELETE /firmware
# Usage: fw-remove <root_host:port> <from_sig> [/resource_path]
fw_remove() {
  local root_hp="$1" from_sig="$2" path="${3:-/firmware}"
  if [ -z "$root_hp" ] || [ -z "$from_sig" ]; then
    _err "Usage: $0 fw-remove <root_host:port> <from_sig> [/resource_path]"
    exit 1
  fi
  local API="http://$root_hp"
  _header "Client → DELETE $API$path"
  curl -s -X DELETE "$API/firmware?from_signature=$from_sig&resource_path=$path" \
    | (command -v jq >/dev/null 2>&1 && jq . || cat)
}

# GET /alerts
# Usage: alerts-read <root_host:port> <from_sig> [/resource_path]
alerts_read() {
  local root_hp="$1" from_sig="$2" path="${3:-/alerts}"
  if [ -z "$root_hp" ] || [ -z "$from_sig" ]; then
    _err "Usage: $0 alerts-read <root_host:port> <from_sig> [/resource_path]"
    exit 1
  fi
  local API="http://$root_hp"
  _header "Client → GET $API$path"
  curl -s -X GET "$API/alerts?from_signature=$from_sig&resource_path=$path" \
    | (command -v jq >/dev/null 2>&1 && jq . || cat)
}

# POST /alerts
# Usage: alerts-create <root_host:port> <from_sig> [/resource_path]
alerts_create() {
  local root_hp="$1" from_sig="$2" path="${3:-/alerts}"
  if [ -z "$root_hp" ] || [ -z "$from_sig" ]; then
    _err "Usage: $0 alerts-create <root_host:port> <from_sig> [/resource_path]"
    exit 1
  fi
  local API="http://$root_hp"
  _header "Client → POST $API$path"
  curl -s -X POST "$API/alerts?from_signature=$from_sig&resource_path=$path" \
    | (command -v jq >/dev/null 2>&1 && jq . || cat)
}

# PUT /control/led
# Usage: control-led <root_host:port> <from_sig> [/resource_path]
control_led() {
  local root_hp="$1" from_sig="$2" path="${3:-/control/led}"
  if [ -z "$root_hp" ] || [ -z "$from_sig" ]; then
    _err "Usage: $0 control-led <root_host:port> <from_sig> [/resource_path]"
    exit 1
  fi
  local API="http://$root_hp"
  _header "Client → PUT $API$path"
  curl -s -X PUT "$API/control/led?from_signature=$from_sig&resource_path=$path" \
    | (command -v jq >/dev/null 2>&1 && jq . || cat)
}

# DELETE /control/motor
# Usage: control-motor-stop <root_host:port> <from_sig> [/resource_path]
control_motor_stop() {
  local root_hp="$1" from_sig="$2" path="${3:-/control/motor}"
  if [ -z "$root_hp" ] || [ -z "$from_sig" ]; then
    _err "Usage: $0 control-motor-stop <root_host:port> <from_sig> [/resource_path]"
    exit 1
  fi
  local API="http://$root_hp"
  _header "Client → DELETE $API$path"
  curl -s -X DELETE "$API/control/motor?from_signature=$from_sig&resource_path=$path" \
    | (command -v jq >/dev/null 2>&1 && jq . || cat)
}
# =========[ MULTISIG (approver-side) ]=========
msig_info() {
  hdr "Multisig Info"
  node "$ROOT_PATH/interact.js" msigInfo | (command -v jq >/dev/null 2>&1 && jq . || cat)
}

msig_is_approver() {
  local addr="$1"
  [[ -z "$addr" ]] && { err "Usage: $0 msig-is-approver <address>"; exit 1; }
  hdr "Is Approver?"
  node "$ROOT_PATH/interact.js" msigIsApprover "$addr"
}

approve_create_policy() {
  local from_role="$1" to_role="$2" ops="$3" ctx="${4:-device:v1}"
  [[ -z "$from_role" || -z "$to_role" || -z "$ops" ]] && {
    err "Usage: $0 approve-create-policy <fromRole|num> <toRole|num> <opsCsv|mask> [ctx]"
    exit 1
  }
  hdr "Approve Create Policy"
  node "$ROOT_PATH/interact.js" approveCreatePolicy "$from_role" "$to_role" "$ops" "$ctx"
}

msig_approved_events() {
  local from_block="${1:-0}"
  hdr "MsigApproved events (from block $from_block)"
  # Requires a matching command in interact.js; otherwise will error.
  node "$ROOT_PATH/interact.js" msigApprovedEvents "$from_block" \
    | (command -v jq >/dev/null 2>&1 && jq . || cat)
}

whoami() {
  hdr "Who am I (prefunded signer index)"
  node "$ROOT_PATH/interact.js" whoami | (command -v jq >/dev/null 2>&1 && jq . || cat)
}

# =========[ HELP ]=========
help(){
  echo -e "${CYAN}Usage:${RESET} $0 <command> [args]"
  echo
  echo -e "${CYAN}Client lifecycle${RESET}"
  echo "  client-start-flask                       Start Flask (/acknowledgement) to receive ACK"
  echo "  init-chain-client                 Generate keys under data/"
  echo "  register <id> <name> <type> <root_host:port>   Register to root (includes callback)"
  echo "  await-ack [seconds]               Wait for ACK artifacts (default 120s)"
  echo "  start-chain-client                Start Besu (requires ACK)"
  echo "  stop-chain-client                 Stop Besu"
  echo "  restart-chain-client              Restart Besu"
  echo "  reinit-chain-client               Wipe local state and reconfigure"
  echo "  status                            Show readiness & processes"
  echo
  echo -e "${CYAN}Multisig (approver tools)${RESET}"
  echo "  msig-info                           Read multisig status"
  echo "  msig-is-approver <address>          Check if address is approver"
  echo "  approve-create-policy <from> <to> <ops> [ctx]  Approve a pending createPolicy"
  echo "  msig-approved-events [fromBlock]    Audit approval events (if supported in interact.js)"
  echo 
  echo -e "${CYAN}Client (Other Nodes): Registration + Access${RESET}"
  echo "  client-access <root_host:port> <from_sig> <METHOD> </path> [expiry] [allow_delegation] [depth]"
  echo "  temp-read <root_host:port> <from_sig> [/path]         GET /temperature"
  echo "  temp-write <root_host:port> <from_sig> [/path]        POST /temperature"
  echo "  fw-update <root_host:port> <from_sig> [/path]         PUT /firmware"
  echo "  fw-remove <root_host:port> <from_sig> [/path]         DELETE /firmware"
  echo "  alerts-read <root_host:port> <from_sig> [/path]       GET /alerts"
  echo "  alerts-create <root_host:port> <from_sig> [/path]     POST /alerts"
  echo "  control-led <root_host:port> <from_sig> [/path]       PUT /control/led"
  echo "  control-motor-stop <root_host:port> <from_sig> [/path]  DELETE /control/motor"
  echo
  echo -e "${CYAN}Chain helpers${RESET}"
  echo "  whoami                              Show signer & balance (via interact.js)"
}

# =========[ DISPATCH ]=========
cmd="${1:-}"; shift || true
case "$cmd" in
  init-chain-client)        init_chain_client ;;
  reinit-chain-client)      reinit_chain_client ;;
  start-flask-client)       client_start_service ;;
  start-chain-client)       start_chain_client ;;
  stop-chain-client)        stop_chain_client ;;
  restart-chain-client)     restart_chain_client ;;
  register)                 register_node "$@" ;;
  status)                   status ;;
  
  # Client: Access
  client-access)       client_access "$@" ;;
  temp-read)           temp_read "$@" ;;
  temp-write)          temp_write "$@" ;;
  fw-update)           fw_update "$@" ;;
  fw-remove)           fw_remove "$@" ;;
  alerts-read)         alerts_read "$@" ;;
  alerts-create)       alerts_create "$@" ;;
  control-led)         control_led "$@" ;;
  control-motor-stop)  control_motor_stop "$@" ;;

  msig-info)                 msig_info ;;
  msig-is-approver)          msig_is_approver "$@" ;;
  approve-create-policy)     approve_create_policy "$@" ;;
  msig-approved-events)      msig_approved_events "$@" ;;
  help|"")                  help ;;
  *)                        err "Unknown command: $cmd"; help; exit 1 ;;
  
esac

# /start_client_services.sh register FOG001 "Weather Station" Fog 192.168.0.10:5000