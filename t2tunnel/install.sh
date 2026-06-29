#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PANEL_DIR="${REPO_DIR}/webpanel"
PANEL_BIN="t2panel"
PANEL_PORT="${1:-${PANEL_PORT:-}}"
SERVER_ROLE=""
GO_VERSION="1.22.5"

P=$'\033[38;5;80m'; C=$'\033[38;5;87m'; A=$'\033[38;5;215m'
G=$'\033[38;5;83m'; R=$'\033[38;5;203m'; D=$'\033[38;5;245m'
W=$'\033[1;38;5;255m'; N=$'\033[0m'; B=$'\033[1m'

line() { printf "${P}%s${N}\n" "------------------------------------------------------------"; }
ok()   { printf "  ${G}[ok]${N} %s\n" "$*"; }
inf()  { printf "  ${C}[*]${N}  %s\n" "$*"; }
wrn()  { printf "  ${A}[!]${N}  %s\n" "$*"; }
err()  { printf "  ${R}[x]${N}  %s\n" "$*"; }

spin() {
  local msg="$1"; shift
  local fr='|/-\' i=0 logf; logf=$(mktemp)
  ( "$@" >"$logf" 2>&1 ) & local pid=$!
  printf "  ${P}|${N}  %s" "$msg"
  while kill -0 "$pid" 2>/dev/null; do
    i=$(( (i+1) % 4 )); printf "\r  ${P}%s${N}  %s" "${fr:$i:1}" "$msg"; sleep 0.1
  done
  if wait "$pid"; then printf "\r  ${G}[ok]${N} %s            \n" "$msg"; rm -f "$logf"
  else printf "\r  ${R}[x]${N}  %s            \n" "$msg"; printf "${D}"; sed 's/^/      /' "$logf" | tail -n 18; printf "${N}"; rm -f "$logf"; return 1; fi
}

banner() {
  clear 2>/dev/null || true
  printf "\n${P}${B}"
  cat <<'ART'
        ########  ######   ##  ##   ####    #####  ##  ##
           ##        ##     ##  ##  ##  ##  ##      ##  ##
           ##      #####   ######  ######   ####   ######
           ##         ##   ##  ##  ##  ##      ##   ##  ##
           ##     #######  ##  ##  ##  ##  #####    ##  ##
ART
  printf "${N}"
  printf "        ${C}T U N N E L${N}   ${D}-   web panel bootstrap   v2.3.1${N}\n\n"
  line
}

ensure_go() {
  local need=1
  if command -v go >/dev/null 2>&1; then
    local cur major minor
    cur=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | sed 's/go//')
    major=$(echo "$cur" | cut -d. -f1)
    minor=$(echo "$cur" | cut -d. -f2)
    if [ "${major:-0}" -gt 1 ] 2>/dev/null || { [ "${major:-0}" -eq 1 ] && [ "${minor:-0}" -ge 22 ]; } 2>/dev/null; then
      need=0
    fi
  fi
  if [ "$need" -eq 1 ]; then
    local arch goarch
    arch=$(uname -m)
    case "$arch" in
      x86_64) goarch="amd64" ;;
      aarch64) goarch="arm64" ;;
      armv7l) goarch="armv6l" ;;
      *) goarch="amd64" ;;
    esac
    apt-get remove -y golang-go >/dev/null 2>&1 || true
    rm -rf /usr/local/go
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" -o /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    grep -q "/usr/local/go/bin" /etc/profile 2>/dev/null || echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
  fi
  export PATH=$PATH:/usr/local/go/bin
}

if [[ "${EUID}" -ne 0 ]]; then err "run with sudo:  sudo bash install.sh"; exit 1; fi
banner

if [[ -z "${PANEL_PORT}" ]]; then
  printf "\n  ${W}This server is:${N}\n"
  printf "    ${P}1)${N} Iran server     ${D}(panel port 2331)${N}\n"
  printf "    ${P}2)${N} Foreign server  ${D}(panel port 2332)${N}\n"
  while true; do
    printf "  ${C}Choose [1/2]: ${N}"
    read -r CHOICE || true
    case "${CHOICE}" in
      1) PANEL_PORT=2331; SERVER_ROLE="Iran";    break ;;
      2) PANEL_PORT=2332; SERVER_ROLE="Foreign"; break ;;
      *) wrn "type 1 or 2" ;;
    esac
  done
  ok "selected: ${SERVER_ROLE} server  ->  port ${PANEL_PORT}"
fi
PANEL_ADDR="127.0.0.1:${PANEL_PORT}"

printf "\n  ${W}1) Prerequisites${N}\n"
if command -v apt-get >/dev/null 2>&1; then
  spin "apt update"  apt-get update -y
  spin "install libpcap-dev, build-essential, iptables, curl, tar"  apt-get install -y libpcap-dev build-essential iptables curl tar
else
  wrn "apt not found. Install manually: libpcap-dev build-essential iptables curl tar"
fi

spin "ensure Go >= ${GO_VERSION}"  ensure_go
if ! command -v go >/dev/null 2>&1; then err "Go not found after install. Install it and re-run."; exit 1; fi
ok "go ready: $(go version | awk '{print $3}')"

printf "\n  ${W}2) Build web panel${N}\n"
if [[ ! -d "${PANEL_DIR}" ]]; then
  err "panel dir not found: ${PANEL_DIR}"
  err "make sure webpanel/panel.go and webpanel/panel.html are next to this script."
  exit 1
fi
cd "${PANEL_DIR}"
[[ -f go.mod ]] || spin "go mod init"  go mod init t2panel
export GOTOOLCHAIN=local
export GOPROXY="https://goproxy.io,direct"
spin "go build (panel)"  go build -trimpath -ldflags "-s -w" -o "${PANEL_BIN}" .
ok "panel built -> ${PANEL_DIR}/${PANEL_BIN}"

cp -f "${PANEL_DIR}/panel.html" "${REPO_DIR}/panel.html" 2>/dev/null && ok "panel.html در دسترسِ پنل قرار گرفت" || true

printf "\n  ${W}3) Credentials${N}\n"
DB_FILE="${PANEL_DIR}/panel.db.json"
if [[ -f "${DB_FILE}" ]]; then
  wrn "existing panel.db.json found."
  printf "  ${D}reset credentials? old password stops working [y/N]: ${N}"
  read -r ANS || true
  if [[ "${ANS,,}" == "y" || "${ANS,,}" == "yes" ]]; then rm -f "${DB_FILE}"; ok "old credentials removed"; fi
fi

printf "\n  ${W}4) Start panel${N}\n"
pkill -f "${PANEL_BIN} .*-addr ${PANEL_ADDR}" 2>/dev/null || true
sleep 1
LOGF="${PANEL_DIR}/panel.run.log"
nohup "./${PANEL_BIN}" -addr "${PANEL_ADDR}" -repo "${REPO_DIR}" >"${LOGF}" 2>&1 &
PANEL_PID=$!
sleep 2
if ! kill -0 "${PANEL_PID}" 2>/dev/null; then
  err "panel failed to start. log:"; printf "${D}"; tail -n 30 "${LOGF}"; printf "${N}"; exit 1
fi

PW=$(grep -m1 "password :" "${LOGF}" | sed -E 's/.*password : *//; s/\x1b\[[0-9;]*m//g' | tr -d '[:space:]' || true)
USER=$(grep -m1 "username :" "${LOGF}" | sed -E 's/.*username : *//; s/\x1b\[[0-9;]*m//g' | tr -d '[:space:]' || true)
[[ -z "${USER}" ]] && USER="admin"
PUBIP=$(curl -s --max-time 4 ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
[[ -z "${PUBIP}" ]] && PUBIP="YOUR_SERVER_IP"
ok "panel running (pid ${PANEL_PID})"

echo; line
printf "  ${G}${B}PANEL IS UP — finish setup in your browser${N}\n"
line
printf "  ${W}URL${N}        ${C}http://${PANEL_ADDR}${N}\n"
printf "  ${W}username${N}   ${B}${USER}${N}\n"
if [[ -n "${PW}" ]]; then
  printf "  ${W}password${N}   ${G}${B}${PW}${N}\n"
else
  printf "  ${W}password${N}   ${D}(set previously — use your saved password)${N}\n"
fi
line
printf "\n  ${A}The panel listens on 127.0.0.1 only (safe, not exposed).${N}\n"
printf "  ${A}To open it from your PC, make an SSH tunnel first:${N}\n\n"
printf "    ${W}ssh -L ${PANEL_PORT}:127.0.0.1:${PANEL_PORT} root@${PUBIP}${N}\n\n"
printf "  ${D}then open in your browser:${N}  ${C}http://127.0.0.1:${PANEL_PORT}${N}\n"
echo; line
printf "  ${D}next steps (all inside the panel):${N}\n"
printf "    ${P}1.${N} login with the credentials above\n"
printf "    ${P}2.${N} Dashboard  ->  Install prerequisites  ->  Build binary\n"
printf "    ${P}3.${N} Config     ->  pick role + transport (tls)  ->  Save service\n"
printf "    ${P}4.${N} Dashboard  ->  Start service\n"
printf "    ${P}5.${N} Logs       ->  watch it run\n"
line
printf "\n  ${D}panel log:${N}     ${LOGF}\n"
printf "  ${D}stop panel:${N}    sudo pkill -f ${PANEL_BIN}\n"
printf "  ${D}reset login:${N}   delete ${DB_FILE} and re-run\n\n"
