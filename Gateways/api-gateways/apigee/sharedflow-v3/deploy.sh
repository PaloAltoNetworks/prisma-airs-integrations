#!/usr/bin/env bash
# Deploys the PANW-AIRS v3 SharedFlow, its encrypted config map, and the example proxies, to one Apigee environment.
#
#   cp example.env .env      # fill in your values
#   ./deploy.sh --env-file=.env
#
# The Prisma AIRS key (AIRS_TOKEN) and the OAuth 2.0 token (AIRS_BEARER, v3.1) are read only from the env file or the
# environment, never from the command line, where other users of the machine could see them. Other settings can be
# overridden on the command line:
#   ./deploy.sh --env-file=.env --env=dev --examples=llm,mcp --mcp-url=https://mcp.example.com
# Renewing the OAuth token by hand: put the new one in the env file, then
#   ./deploy.sh --env-file=.env --bearer-only
#
# Needs: gcloud (signed in, with Apigee admin rights on the organization), curl, jq, zip.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APIGEE_API="https://apigee.googleapis.com/v1"

usage() {
  cat <<'EOF'
Usage: ./deploy.sh --env-file=FILE [options]

Required (in the env file, the environment, or as options):
  PROJECT / --project=ID          Google Cloud project; also the Apigee organization unless ORG is set
  ENV / --env=NAME                Apigee environment to deploy into
  SA / --sa=EMAIL                 service account the SharedFlow and the example proxies run as. The SharedFlow's
                                  log step writes to Cloud Logging, so Apigee refuses to deploy it without one.
                                  Grant it roles/logging.logWriter, and roles/aiplatform.user for the LLM example.
  AIRS_TOKEN                      the Prisma AIRS API key (env file or environment only); not needed with
                                  AIRS_AUTH_MODE=bearer
  AIRS_PROFILE / --airs-profile=NAME   the Prisma AIRS security profile (name or UUID)

Optional:
  ORG / --org=NAME                Apigee organization, if not the project id
  KVM_NAME / --kvm-name=NAME      config map name (default airs-config); the bundle copy is changed to match
  SHAREDFLOW_NAME / --sharedflow-name=NAME   (default PANW-AIRS); the example proxies' FlowCallouts follow it
  EXAMPLES / --examples=LIST      example proxies to deploy: llm, mcp, both as llm,mcp, or none (default llm)
  LLM_PROXY_NAME, MCP_PROXY_NAME  their names (default airs-llm-guard, airs-mcp-guard)
  MCP_URL / --mcp-url=URL         the MCP server the MCP example forwards to (required with mcp)
  APIGEE_HOST / --host=HOST       your environment group's host name, to print smoke-test commands
  SMOKE_MODEL                     the Gemini model the smoke tests name (default gemini-3.8-flash)
  AIRS_AUTH_MODE / --auth-mode=MODE   apikey or bearer (v3.1): written to the config map as airs_auth_mode, the mode of
                                  every proxy that sets no prismaAirsAuthMode of its own. Unset leaves the entry as it is
  AIRS_BEARER                     the Prisma AIRS OAuth 2.0 token (v3.1; env file or environment only), written to the config
                                  map as airs_bearer, before airs_auth_mode. Whitespace around it is dropped; it must then be
                                  1 to 4,096 printable ASCII characters with no spaces, as v3 requires. If the map already
                                  held a token, what this run switches to bearer mode (airs_auth_mode, or flow hooks whose
                                  HOOK_SETTINGS say bearer) comes last, 310 s after the token, so no runtime instance sends
                                  the old token in bearer mode
  --bearer-only                   renewal by hand: writes only airs_bearer to the existing config map and deploys nothing
                                  (needs PROJECT, ENV and AIRS_BEARER). The runtime uses it within about five minutes
  HOOK_ROUTES / --hook-routes=LIST   flow hooks: the base paths v3 scans from the environment's pre-target and post-target
                                  hooks, comma-separated (/airs-llm,/airs-mcp), each exactly as the proxy's base path.
                                  Reads both hook points before anything else and stops, with nothing changed, if either
                                  holds another SharedFlow; then writes the config map entry airs_hook, deploys the two hook
                                  SharedFlows and attaches them. Every other proxy in the environment passes untouched.
  HOOK_SETTINGS / --hook-settings=JSON  settings for those routes, as a JSON object of names and values (default {})
  HOOK_ATTACH / --hook-attach=yes|no    with HOOK_ROUTES: no writes airs_hook and deploys the hook SharedFlows without
                                  reading or attaching any hook point, for points that hold a SharedFlow of yours: add a
                                  FlowCallout to each hook SharedFlow from yours (default yes)
EOF
  exit "${1:-0}"
}

ENV_FILE=""
for arg in "$@"; do
  case "$arg" in
    --env-file=*) ENV_FILE="${arg#*=}" ;;
    -h|--help)    usage 0 ;;
  esac
done
if [[ -n "$ENV_FILE" ]]; then
  [[ -f "$ENV_FILE" ]] || { echo "No env file at $ENV_FILE" >&2; exit 1; }
  set -a; # shellcheck disable=SC1090
  source "$ENV_FILE"; set +a
fi

PROJECT="${PROJECT:-}"; ORG="${ORG:-}"; ENV="${ENV:-}"; SA="${SA:-}"
AIRS_TOKEN="${AIRS_TOKEN:-}"; AIRS_PROFILE="${AIRS_PROFILE:-}"
AIRS_AUTH_MODE="${AIRS_AUTH_MODE:-}"; AIRS_BEARER="${AIRS_BEARER:-}"; BEARER_ONLY=no
KVM_NAME="${KVM_NAME:-airs-config}"; SHAREDFLOW_NAME="${SHAREDFLOW_NAME:-PANW-AIRS}"
EXAMPLES="${EXAMPLES:-llm}"; LLM_PROXY_NAME="${LLM_PROXY_NAME:-airs-llm-guard}"; MCP_PROXY_NAME="${MCP_PROXY_NAME:-airs-mcp-guard}"
MCP_URL="${MCP_URL:-}"; APIGEE_HOST="${APIGEE_HOST:-}"; SMOKE_MODEL="${SMOKE_MODEL:-gemini-3.8-flash}"
HOOK_ROUTES="${HOOK_ROUTES:-}"; HOOK_SETTINGS="${HOOK_SETTINGS:-}"; HOOK_ATTACH="${HOOK_ATTACH:-yes}"

for arg in "$@"; do
  case "$arg" in
    --env-file=*) ;;
    --project=*)          PROJECT="${arg#*=}" ;;
    --org=*)              ORG="${arg#*=}" ;;
    --env=*)              ENV="${arg#*=}" ;;
    --sa=*)               SA="${arg#*=}" ;;
    --airs-profile=*)     AIRS_PROFILE="${arg#*=}" ;;
    --kvm-name=*)         KVM_NAME="${arg#*=}" ;;
    --sharedflow-name=*)  SHAREDFLOW_NAME="${arg#*=}" ;;
    --examples=*)         EXAMPLES="${arg#*=}" ;;
    --mcp-url=*)          MCP_URL="${arg#*=}" ;;
    --host=*)             APIGEE_HOST="${arg#*=}" ;;
    --hook-routes=*)      HOOK_ROUTES="${arg#*=}" ;;
    --hook-settings=*)    HOOK_SETTINGS="${arg#*=}" ;;
    --hook-attach=*)      HOOK_ATTACH="${arg#*=}" ;;
    --auth-mode=*)        AIRS_AUTH_MODE="${arg#*=}" ;;
    --bearer-only)        BEARER_ONLY=yes ;;
    --airs-token=*)       echo "The key is not accepted on the command line: put AIRS_TOKEN in the env file." >&2; exit 1 ;;
    --airs-bearer=*)      echo "The OAuth token is not accepted on the command line: put AIRS_BEARER in the env file." >&2; exit 1 ;;
    *) echo "Unknown option: $arg" >&2; usage 1 ;;
  esac
done

[[ -n "$PROJECT" ]]      || { echo "Missing PROJECT" >&2; usage 1; }
[[ -n "$ENV" ]]          || { echo "Missing ENV" >&2; usage 1; }
# v3.1: the mode and the token, checked as v3 checks them, before anything is written. The token is never printed.
trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }
AIRS_AUTH_MODE="$(trim "$AIRS_AUTH_MODE" | tr '[:upper:]' '[:lower:]')"
[[ -z "$AIRS_AUTH_MODE" || "$AIRS_AUTH_MODE" == apikey || "$AIRS_AUTH_MODE" == bearer ]] || { echo "AIRS_AUTH_MODE: apikey or bearer" >&2; exit 1; }
AIRS_BEARER="$(trim "$AIRS_BEARER")"
if [[ -n "$AIRS_BEARER" ]] && ! ( LC_ALL=C; [[ ${#AIRS_BEARER} -le 4096 && "$AIRS_BEARER" =~ ^[!-~]+$ ]] ); then
  echo "AIRS_BEARER: not a token v3 can send (1 to 4,096 printable ASCII characters, no spaces); nothing was written" >&2; exit 1
fi
[[ "$AIRS_BEARER" != your-prisma-airs-oauth-token ]] || { echo "AIRS_BEARER still holds example.env's placeholder: put your token there" >&2; exit 1; }
if [[ "$BEARER_ONLY" == yes ]]; then
  [[ -n "$AIRS_BEARER" ]] || { echo "--bearer-only needs AIRS_BEARER (env file or environment)" >&2; exit 1; }
else
  [[ "$AIRS_TOKEN" != your-prisma-airs-api-key ]] || { echo "AIRS_TOKEN still holds example.env's placeholder: put your key there, or leave it empty with AIRS_AUTH_MODE=bearer" >&2; exit 1; }
  [[ -n "$SA" ]]           || { echo "Missing SA (the SharedFlow can't be deployed without a service account)" >&2; usage 1; }
  [[ "$AIRS_AUTH_MODE" != bearer || -n "$AIRS_BEARER" ]] || { echo "AIRS_AUTH_MODE=bearer needs AIRS_BEARER (env file or environment)" >&2; exit 1; }
  [[ -n "$AIRS_TOKEN" || "$AIRS_AUTH_MODE" == bearer ]] || { echo "Missing AIRS_TOKEN (env file or environment), or set AIRS_AUTH_MODE=bearer and AIRS_BEARER" >&2; usage 1; }
  [[ -n "$AIRS_PROFILE" ]] || { echo "Missing AIRS_PROFILE" >&2; usage 1; }
fi
ORG="${ORG:-$PROJECT}"
[[ "$KVM_NAME" =~ ^[A-Za-z0-9._-]+$ ]]        || { echo "KVM_NAME: letters, digits, '.', '_' and '-' only" >&2; exit 1; }
[[ "$SHAREDFLOW_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "SHAREDFLOW_NAME: letters, digits, '.', '_' and '-' only" >&2; exit 1; }
[[ "$LLM_PROXY_NAME" =~ ^[A-Za-z0-9._-]+$ ]]  || { echo "LLM_PROXY_NAME: letters, digits, '.', '_' and '-' only" >&2; exit 1; }
[[ "$MCP_PROXY_NAME" =~ ^[A-Za-z0-9._-]+$ ]]  || { echo "MCP_PROXY_NAME: letters, digits, '.', '_' and '-' only" >&2; exit 1; }
# The MCP URL goes into the example's XML as written, so it takes no query string and no characters XML would need escaped.
case ",$EXAMPLES," in *,mcp,*) [[ "$MCP_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$ ]] || { echo "The MCP example needs MCP_URL=https://host[:port][/path], with no query string" >&2; exit 1; } ;; esac

for c in gcloud curl jq zip; do command -v "$c" >/dev/null || { echo "$c is not on PATH" >&2; exit 1; }; done
# Flow hooks: each route a base path, and the settings a JSON object (both checked before anything is deployed).
if [[ -n "$HOOK_ROUTES" ]]; then
  IFS=',' read -r -a HOOK_LIST <<< "$HOOK_ROUTES"
  # v3 lists a proxy only on an exact match of its base path, which never ends in / (unless it is /) and has no empty part.
  for r in "${HOOK_LIST[@]}"; do [[ "$r" =~ ^/([A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*)?$ ]] || { echo "HOOK_ROUTES: '$r' is not a base path (/name or /name/part, no / at the end)" >&2; exit 1; }; done
  [[ -n "$HOOK_SETTINGS" ]] || HOOK_SETTINGS='{}'
  echo "$HOOK_SETTINGS" | jq -e 'type == "object"' >/dev/null 2>&1 || { echo "HOOK_SETTINGS: not a JSON object" >&2; exit 1; }
  [[ "$HOOK_ATTACH" == yes || "$HOOK_ATTACH" == no ]] || { echo "HOOK_ATTACH: yes or no" >&2; exit 1; }
fi
# A fresh access token before every call: gcloud caches it and renews it as needed, so a long run never outlives it.
# Called as a statement, so a missing token stops the script (and its subshell callers) at once.
TOKEN=""
refresh() {
  TOKEN="$(gcloud auth print-access-token 2>/dev/null || true)"
  [[ -n "$TOKEN" ]] || { printf "  failed: gcloud gave no access token: run gcloud auth login, then deploy again\n" >&2; exit 1; }
}
refresh

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
MODE_AT=""; MODE_LATER=""; HOOKS_LATER=""   # set by setup_kvm when what switches to bearer mode must wait for a replaced token

step() { printf "\n== %s\n" "$*"; }
ok()   { printf "  ok: %s\n" "$*"; }
die()  { printf "  failed: %s\n" "$*" >&2; exit 1; }

# One API call; prints the body, then the HTTP status on its own last line.
api() {
  local method="$1" path="$2" body="${3:-}"
  refresh
  local args=(-sS -X "$method" -H "Authorization: Bearer $TOKEN" -w $'\n%{http_code}')
  if [[ -n "$body" ]]; then
    args+=(-H "Content-Type: application/json" --data-binary @-)
    printf '%s' "$body" | curl "${args[@]}" "$APIGEE_API$path"
  else
    curl "${args[@]}" "$APIGEE_API$path"
  fi
}
status_of() { refresh; curl -sS -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$APIGEE_API$1"; }
lower_trim() { trim "$1" | tr '[:upper:]' '[:lower:]'; }
# A settings JSON object's prismaAirsAuthMode, trimmed and lowercased as v3 reads it, or nothing.
settings_mode() { local v; v="$(printf '%s' "$1" | jq -r '(.prismaAirsAuthMode // "") | tostring' 2>/dev/null || true)"; lower_trim "$v"; }
# An entry's value, or nothing if it isn't there: only for entries that hold no secret (airs_auth_mode, airs_hook).
entry_value() {
  local resp
  resp="$(api GET "$1/entries/$2")"
  [[ "${resp##*$'\n'}" == 200 ]] && printf '%s' "${resp%$'\n'*}" | jq -r '.value // empty'
  return 0
}

# ----- the config map: encrypted; the key and the token are never printed, nor put on a command line ---------------
put_entry() {   # map path, entry name, value (from a variable, never argv to another program)
  local payload resp code
  payload="$(V="$3" jq -n --arg n "$2" '{name:$n, value:env.V}')"
  if [[ "$(status_of "$1/entries/$2")" == "200" ]]; then resp="$(api PUT "$1/entries/$2" "$payload")"; else resp="$(api POST "$1/entries" "$payload")"; fi
  code="${resp##*$'\n'}"; [[ "$code" =~ ^20[01]$ ]] || die "writing entry $2: HTTP $code"
  ok "entry $2 written"
}
# Renewal by hand (--bearer-only): the map must exist; only airs_bearer changes, and nothing is deployed.
renew_bearer() {
  step "OAuth token in config map $KVM_NAME, environment $ENV"
  local kvm="/organizations/$ORG/environments/$ENV/keyvaluemaps/$KVM_NAME"
  [[ "$(status_of "$kvm")" == "200" ]] || die "no config map $KVM_NAME in $ENV: run a full deploy first"
  put_entry "$kvm" airs_bearer "$AIRS_BEARER"
}
setup_kvm() {
  step "Config map $KVM_NAME in environment $ENV"
  local kvm="/organizations/$ORG/environments/$ENV/keyvaluemaps/$KVM_NAME" resp code
  if [[ "$(status_of "$kvm")" == "200" ]]; then
    ok "it exists"
  else
    resp="$(api POST "/organizations/$ORG/environments/$ENV/keyvaluemaps" "$(jq -n --arg n "$KVM_NAME" '{name:$n, encrypted:true}')")"
    code="${resp##*$'\n'}"; [[ "$code" =~ ^20[01]$ ]] || die "creating it: HTTP $code"
    ok "created, encrypted"
  fi
  [[ -n "$AIRS_TOKEN" ]] && put_entry "$kvm" airs_token "$AIRS_TOKEN"
  put_entry "$kvm" airs_profile "$AIRS_PROFILE"
  # The token before the mode. A first token is read at once, so the mode can follow it at once. A token that replaces one
  # already in the map reaches each runtime instance only when its 300 s cache of the old one runs out, while a mode can be
  # read sooner (VERIFICATION.md, L24): switching to bearer then would send the old token for up to five minutes. So what
  # this run switches to bearer mode, the map's airs_auth_mode or flow hooks whose settings say bearer, comes last, 310 s
  # after the token, once the SharedFlow and the examples are deployed. Any answer but 404 counts as a token there.
  if [[ -n "$AIRS_BEARER" ]]; then
    local had_token mode_now hooks_now
    had_token="$(status_of "$kvm/entries/airs_bearer")" || die "reading entry airs_bearer: no answer"
    mode_now="$(lower_trim "$(entry_value "$kvm" airs_auth_mode)")"
    put_entry "$kvm" airs_bearer "$AIRS_BEARER"
    if [[ "$had_token" != 404 ]]; then
      [[ "$AIRS_AUTH_MODE" == bearer && "$mode_now" != bearer ]] && MODE_LATER=yes
      if [[ -n "$HOOK_ROUTES" && "$(settings_mode "$HOOK_SETTINGS")" == bearer ]]; then
        hooks_now="$(entry_value "$kvm" airs_hook)"
        [[ "$(settings_mode "$(printf '%s' "$hooks_now" | jq -c '.settings // {}' 2>/dev/null || true)")" == bearer ]] || HOOKS_LATER=yes
      fi
      if [[ -n "$MODE_LATER$HOOKS_LATER" ]]; then
        local what="${MODE_LATER:+airs_auth_mode}"; [[ -n "$HOOKS_LATER" ]] && what="${what:+$what, }the flow hooks"
        MODE_AT=$(( $(date +%s) + 310 ))
        ok "the map already held a token: bearer mode starts last ($what), once every runtime instance has the new token"
      fi
    fi
  fi
  [[ -n "$AIRS_AUTH_MODE" && -z "$MODE_LATER" ]] && put_entry "$kvm" airs_auth_mode "$AIRS_AUTH_MODE"
  return 0
}
# What switches to bearer mode, when it had to wait for a replaced token (setup_kvm): the mode, then the flow hooks.
write_last() {
  step "Bearer mode, after the new token"
  local now; now="$(date +%s)"
  if (( MODE_AT > now )); then
    echo "  waiting $(( MODE_AT - now )) s, so every runtime instance has the new token before bearer mode starts"
    sleep "$(( MODE_AT - now ))"
  fi
  if [[ -n "$MODE_LATER" ]]; then put_entry "/organizations/$ORG/environments/$ENV/keyvaluemaps/$KVM_NAME" airs_auth_mode "$AIRS_AUTH_MODE"; fi
  if [[ -n "$HOOKS_LATER" ]]; then setup_hooks; fi
  return 0
}

# ----- bundles -------------------------------------------------------------------------------------------------
import_bundle() {   # kind (sharedflows|apis), name, zip; prints the new revision
  local resp code body rev
  refresh
  resp="$(curl -sS -X POST -H "Authorization: Bearer $TOKEN" -F "file=@$3" -w $'\n%{http_code}' \
          "$APIGEE_API/organizations/$ORG/$1?action=import&name=$2")"
  code="${resp##*$'\n'}"; body="${resp%$'\n'*}"
  [[ "$code" =~ ^20[01]$ ]] || die "importing $2: HTTP $code: $body"
  rev="$(echo "$body" | jq -r '.revision // empty')"; [[ -n "$rev" ]] || die "importing $2: no revision returned"
  echo "$rev"
}

deploy_revision() {   # kind, name, revision; always with the service account
  local resp code
  resp="$(api POST "/organizations/$ORG/environments/$ENV/$1/$2/revisions/$3/deployments?override=true&serviceAccount=$SA")"
  code="${resp##*$'\n'}"; [[ "$code" =~ ^20[01]$ ]] || die "deploying $2 revision $3: HTTP $code: ${resp%$'\n'*}"
}

wait_ready() {   # kind, name, revision: until that revision's deployment is READY (up to 5 minutes)
  local state
  for _ in $(seq 1 60); do
    refresh
    state="$(curl -sS -H "Authorization: Bearer $TOKEN" \
             "$APIGEE_API/organizations/$ORG/environments/$ENV/$1/$2/revisions/$3/deployments" | jq -r '.state // empty')"
    [[ "$state" == "READY" ]] && { ok "$2 revision $3 is READY"; return 0; }
    [[ "$state" == "ERROR" ]] && die "$2 revision $3: the deployment reports ERROR (see the Apigee console)"
    sleep 5
  done
  die "$2 revision $3 not READY after 5 minutes"
}

deploy_sharedflow() {
  step "SharedFlow $SHAREDFLOW_NAME"
  cp -R "$HERE/PANW-AIRS" "$WORK/sf"
  local b="$WORK/sf/sharedflowbundle"
  if [[ "$SHAREDFLOW_NAME" != "PANW-AIRS" ]]; then
    sed -i.bak "s/name=\"PANW-AIRS\"/name=\"$SHAREDFLOW_NAME\"/" "$b/PANW-AIRS.xml" && rm "$b/PANW-AIRS.xml.bak"
    mv "$b/PANW-AIRS.xml" "$b/$SHAREDFLOW_NAME.xml"
  fi
  if [[ "$KVM_NAME" != "airs-config" ]]; then
    sed -i.bak "s/mapIdentifier=\"airs-config\"/mapIdentifier=\"$KVM_NAME\"/" "$b/policies/KVM-GetAIRSConfig.xml" && rm "$b/policies/KVM-GetAIRSConfig.xml.bak"
  fi
  ( cd "$WORK/sf" && zip -qr "$WORK/sf.zip" sharedflowbundle -x "*.DS_Store" )
  local rev; rev="$(import_bundle sharedflows "$SHAREDFLOW_NAME" "$WORK/sf.zip")"
  ok "imported as revision $rev"
  deploy_revision sharedflows "$SHAREDFLOW_NAME" "$rev"
  wait_ready sharedflows "$SHAREDFLOW_NAME" "$rev"
}

deploy_example() {   # source folder name, proxy name
  step "Example proxy $2"
  rm -rf "$WORK/px"; cp -R "$HERE/examples/$1" "$WORK/px"
  local a="$WORK/px/apiproxy" f
  if [[ "$SHAREDFLOW_NAME" != "PANW-AIRS" ]]; then
    for f in "$a"/policies/FC-*.xml; do
      sed -i.bak "s#<SharedFlowBundle>PANW-AIRS</SharedFlowBundle>#<SharedFlowBundle>$SHAREDFLOW_NAME</SharedFlowBundle>#" "$f" && rm "$f.bak"
    done
  fi
  if [[ "$1" == "airs-mcp-guard" ]]; then
    sed -i.bak "s#<URL>https://mcp.example.com</URL>#<URL>$MCP_URL</URL>#" "$a/targets/default.xml" && rm "$a/targets/default.xml.bak"
  fi
  if [[ "$2" != "$1" ]]; then
    sed -i.bak "s/name=\"$1\"/name=\"$2\"/" "$a/$1.xml" && rm "$a/$1.xml.bak"
    mv "$a/$1.xml" "$a/$2.xml"
  fi
  ( cd "$WORK/px" && zip -qr "$WORK/px.zip" apiproxy -x "*.DS_Store" )
  local rev; rev="$(import_bundle apis "$2" "$WORK/px.zip")"
  ok "imported as revision $rev"
  deploy_revision apis "$2" "$rev"
  wait_ready apis "$2" "$rev"
}

# ----- flow hooks (phase 3): the airs_hook entry, the two hook SharedFlows, and the hook points ---------------------
# A hook point holds one SharedFlow: never replace one that isn't v3's. With HOOK_ATTACH=yes both points are read before
# anything at all is written or deployed, so a point another SharedFlow holds, or a read that fails, changes nothing.
hook_point_of() { if [[ "$1" == request ]]; then echo PreTargetFlowHook; else echo PostTargetFlowHook; fi; }
held_by() {   # point: the SharedFlow it holds, or nothing
  local resp code
  resp="$(api GET "/organizations/$ORG/environments/$ENV/flowhooks/$1")"; code="${resp##*$'\n'}"
  [[ "$code" == "200" ]] || die "reading $1: HTTP $code"
  printf '%s' "${resp%$'\n'*}" | jq -r '.sharedFlow // empty'
}
check_hook_points() {
  step "Flow hook points in environment $ENV"
  local leg name point held
  for leg in request response; do
    name="$SHAREDFLOW_NAME-hook-$leg"; point="$(hook_point_of "$leg")"; held="$(held_by "$point")"
    if [[ -n "$held" && "$held" != "$name" ]]; then
      die "$point holds SharedFlow $held, and deploy.sh never replaces one; nothing was changed. Run again with HOOK_ATTACH=no: it writes airs_hook and deploys $SHAREDFLOW_NAME-hook-request and -response without attaching them. Then add a FlowCallout to $name to $held, and attach the other hook SharedFlow to its point, or call it the same way (README, Flow hooks)"
    fi
    ok "$point: ${held:-empty}"
  done
}

setup_hooks() {
  step "Flow hooks for $HOOK_ROUTES"
  local kvm="/organizations/$ORG/environments/$ENV/keyvaluemaps/$KVM_NAME" payload resp code leg name point held
  payload="$(R="$HOOK_ROUTES" S="$HOOK_SETTINGS" jq -n '{name:"airs_hook", value:({routes:(env.R | split(",")), settings:(env.S | fromjson)} | tojson)}')"
  if [[ "$(status_of "$kvm/entries/airs_hook")" == "200" ]]; then resp="$(api PUT "$kvm/entries/airs_hook" "$payload")"; else resp="$(api POST "$kvm/entries" "$payload")"; fi
  code="${resp##*$'\n'}"; [[ "$code" =~ ^20[01]$ ]] || die "writing entry airs_hook: HTTP $code"
  ok "entry airs_hook written"
  for leg in request response; do
    name="$SHAREDFLOW_NAME-hook-$leg"
    rm -rf "$WORK/hk"; cp -R "$HERE/PANW-AIRS-hook-$leg" "$WORK/hk"
    local b="$WORK/hk/sharedflowbundle"
    if [[ "$name" != "PANW-AIRS-hook-$leg" ]]; then
      sed -i.bak "s/name=\"PANW-AIRS-hook-$leg\"/name=\"$name\"/" "$b/PANW-AIRS-hook-$leg.xml" && rm "$b/PANW-AIRS-hook-$leg.xml.bak"
      mv "$b/PANW-AIRS-hook-$leg.xml" "$b/$name.xml"
    fi
    sed -i.bak "s#<SharedFlowBundle>PANW-AIRS</SharedFlowBundle>#<SharedFlowBundle>$SHAREDFLOW_NAME</SharedFlowBundle>#" "$b"/policies/FC-*.xml && rm "$b"/policies/FC-*.xml.bak
    rm -f "$WORK/hk.zip"; ( cd "$WORK/hk" && zip -qr "$WORK/hk.zip" sharedflowbundle -x "*.DS_Store" )
    local rev; rev="$(import_bundle sharedflows "$name" "$WORK/hk.zip")"
    ok "$name imported as revision $rev"
    deploy_revision sharedflows "$name" "$rev"
    wait_ready sharedflows "$name" "$rev"
  done
  if [[ "$HOOK_ATTACH" == no ]]; then
    ok "not attached (HOOK_ATTACH=no): add a FlowCallout to $SHAREDFLOW_NAME-hook-request to your PreTargetFlowHook SharedFlow and one to $SHAREDFLOW_NAME-hook-response to your PostTargetFlowHook SharedFlow, or attach them yourself"
    return 0
  fi
  # The post-target hook first: if the second attach fails, the listed proxies are left with their replies scanned and
  # their prompts not, which refuses what it can't read, rather than prompts scanned and replies passed unscanned. Each point
  # is read again just before, in case another SharedFlow was attached to it meanwhile.
  for leg in response request; do
    name="$SHAREDFLOW_NAME-hook-$leg"; point="$(hook_point_of "$leg")"; held="$(held_by "$point")"
    [[ -z "$held" || "$held" == "$name" ]] || die "$point now holds SharedFlow $held; airs_hook is written and the hook SharedFlows are deployed, but nothing more was attached. See HOOK_ATTACH=no"
    resp="$(api PUT "/organizations/$ORG/environments/$ENV/flowhooks/$point" "$(jq -n --arg f "$name" '{sharedFlow:$f, continueOnError:false}')")"
    code="${resp##*$'\n'}"
    if [[ ! "$code" =~ ^20[01]$ ]]; then
      [[ "$leg" == request ]] && die "attaching $name to $point: HTTP $code. $SHAREDFLOW_NAME-hook-response is attached to PostTargetFlowHook: run again to finish, or detach it"
      die "attaching $name to $point: HTTP $code"
    fi
    ok "$name attached to $point (it takes about a minute to reach every runtime instance)"
  done
}

if [[ "$BEARER_ONLY" == yes ]]; then
  echo "Renewing the OAuth token in organization $ORG, environment $ENV (nothing is deployed)"
  renew_bearer
  step "Done"
  echo "  Each runtime instance keeps a config map entry it read for 300 s, so the new token is in use within about five minutes."
  exit 0
fi
echo "Deploying to organization $ORG, environment $ENV, as $SA (profile $AIRS_PROFILE, auth mode ${AIRS_AUTH_MODE:-as the config map has it})"
[[ -n "$HOOK_ROUTES" && "$HOOK_ATTACH" == yes ]] && check_hook_points
setup_kvm
deploy_sharedflow
[[ -n "$HOOK_ROUTES" && -z "$HOOKS_LATER" ]] && setup_hooks
case ",$EXAMPLES," in *,llm,*) deploy_example airs-llm-guard "$LLM_PROXY_NAME" ;; esac
case ",$EXAMPLES," in *,mcp,*) deploy_example airs-mcp-guard "$MCP_PROXY_NAME" ;; esac
[[ -n "$MODE_AT" ]] && write_last
step "Done"

if [[ -n "$APIGEE_HOST" ]] && [[ ",$EXAMPLES," == *,llm,* ]]; then
  M="https://$APIGEE_HOST/airs-llm/v1/projects/$PROJECT/locations/global/publishers/google/models/$SMOKE_MODEL:generateContent"
  cat <<EOF

Smoke tests for the LLM example (SMOKE_MODEL picks another model):

  # allowed: the model answers
  curl -sS '$M' -H 'Content-Type: application/json' \\
    --data '{"contents":[{"role":"user","parts":[{"text":"What is the capital of France? Answer in one word."}]}]}'

  # blocked before the model by a profile that detects sensitive data: HTTP 200, a refusal in Gemini's format,
  # and the x-airs-blocked and x-airs-kind headers (add -i to see them)
  curl -sS '$M' -H 'Content-Type: application/json' \\
    --data '{"contents":[{"role":"user","parts":[{"text":"My card number is 4111 1111 1111 1111. Please remember it."}]}]}'
EOF
fi
