#!/usr/bin/env bash
set -Eeuo pipefail

readonly APP_NAME="traffic-telegram-report"
readonly REPORT_SCRIPT="/usr/local/sbin/${APP_NAME}"
readonly CONFIG_FILE="/etc/${APP_NAME}.conf"
readonly SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
readonly TIMER_FILE="/etc/systemd/system/${APP_NAME}.timer"
readonly CF_SERVICE_FILE="/etc/systemd/system/${APP_NAME}-cf.service"
readonly CF_TIMER_FILE="/etc/systemd/system/${APP_NAME}-cf.timer"
readonly CF_POLL_SERVICE_FILE="/etc/systemd/system/${APP_NAME}-poll.service"
readonly CF_POLL_TIMER_FILE="/etc/systemd/system/${APP_NAME}-poll.timer"
readonly CB_SERVICE_FILE="/etc/systemd/system/${APP_NAME}-cb.service"
readonly CB_LISTEN_SCRIPT="/usr/local/sbin/${APP_NAME}-cb"
readonly CB_DEFAULT_PORT="19840"

VNSTAT_WAS_INSTALLED=false
TG_ENABLED=false
CF_ENABLED=false

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
die()  { printf '错误: %s\n' "$*" >&2; exit 1; }

require_root()  { [[ "${EUID}" -eq 0 ]] || die '请使用 root 用户运行，或执行：sudo bash $0'; }

check_debian13() {
  [[ -r /etc/os-release ]] || die '无法识别操作系统。'
  source /etc/os-release
  [[ "${ID:-}" == 'debian' ]] || die "此脚本仅支持 Debian，当前系统为 ${PRETTY_NAME:-未知}。"
  [[ "${VERSION_ID:-}" == '13' ]] || die "此脚本面向 Debian 13，当前版本为 ${VERSION_ID:-未知}。"
  command -v systemctl >/dev/null 2>&1 || die '未检测到 systemd。'
}

# ─── 校验 ───
validate_token() { [[ "$1" =~ ^[0-9]{5,20}:[A-Za-z0-9_-]{20,100}$ ]]; }
validate_chat_id() { [[ "$1" =~ ^-?[0-9]{5,20}$ ]]; }
validate_time() { [[ "$1" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$ ]]; }
validate_cron() {
  local f1 f2 f3 f4 f5
  [[ "$1" =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] || return 1
  f1="${BASH_REMATCH[1]}"; f2="${BASH_REMATCH[2]}"; f3="${BASH_REMATCH[3]}"; f4="${BASH_REMATCH[4]}"; f5="${BASH_REMATCH[5]}"
  [[ "${f1}" =~ ^(\*|\*/[0-9]+|[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*)(/[0-9]+)?$ ]] || return 1
  [[ "${f2}" =~ ^(\*|\*/[0-9]+|[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*)(/[0-9]+)?$ ]] || return 1
  [[ "${f3}" =~ ^(\*|\*/[0-9]+|[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*)(/[0-9]+)?$ ]] || return 1
  [[ "${f4}" =~ ^(\*|\*/[0-9]+|[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*)(/[0-9]+)?$ ]] || return 1
  [[ "${f5}" =~ ^(\*|\*/[0-7]+|[0-7]+(-[0-7]+)?(,[0-7]+(-[0-7]+)?)*)(/[0-9]+)?$ ]] || return 1
  return 0
}
validate_url() { [[ "$1" == https://* ]] && [[ "$1" != *" "* ]] && [[ ${#1} -ge 12 ]]; }
# 机器 ID：1-64 字符，允许中英文/数字/._-:，禁止空白与特殊符号
validate_m_id() {
  local id="$1"
  [[ -n "${id}" ]] || return 1
  [[ ${#id} -le 64 ]] || return 1
  [[ "${id}" != *[[:space:]]* ]] || return 1
  [[ "${id}" != *"'"* && "${id}" != *'"'* && "${id}" != */* && "${id}" != *\\* ]] || return 1
  return 0
}
validate_cf_token() { [[ "$1" =~ ^[A-Za-z0-9._~+/-]{8,256}$ ]]; }
validate_cb_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1024 && $1 <= 65535 )); }
validate_callback_url() {
  [[ "$1" == http://* || "$1" == https://* ]] || return 1
  [[ "$1" != *" "* ]] || return 1
  [[ ${#1} -ge 12 && ${#1} -le 256 ]] || return 1
  return 0
}

# ─── 参数解析（环境变量优先） ───
# TG 可选：t_token + t_id 都提供才启用 TG 日报
resolve_t_token() {
  local val="${t_token:-}"
  [[ -z "${val}" ]] && printf '' && return 0
  validate_token "${val}" || die 'Bot Token 格式无效。'
  printf '%s' "${val}"
}
resolve_t_id() {
  local val="${t_id:-}"
  [[ -z "${val}" ]] && printf '' && return 0
  validate_chat_id "${val}" || die 'Chat ID 应为纯数字，可带负号。'
  printf '%s' "${val}"
}
resolve_t_time() {
  local val="${t_time:-20:00:00}"
  validate_time "${val}" || die "t_time 格式无效，应为 HH:MM:SS，例如 20:00:00。"
  printf '%s' "${val}"
}

# CF 可选：cf_url + cf_token + m_id 都提供才启用 CF 上报
resolve_m_id() {
  local val="${m_id:-}"
  if [[ -z "${val}" ]]; then
    # 仅 CF 模式需要交互输入；纯 TG 模式可无
    if [[ -n "${cf_url:-}" || -n "${cf_token:-}" ]]; then
      read -r -p '请输入机器 ID（如 hk-1）: ' val
    else
      printf ''
      return 0
    fi
  fi
  [[ -z "${val}" ]] && printf '' && return 0
  validate_m_id "${val}" || die "机器 ID 应为 1-64 字，支持中英文、数字及 ._-:（如 香港-1 / hk-1）。"
  printf '%s' "${val}"
}
resolve_cf_token() {
  local val="${cf_token:-}"
  if [[ -z "${val}" ]]; then
    if [[ -n "${cf_url:-}" || -n "${m_id:-}" ]]; then
      read -r -s -p '请输入 CF 上报 Token: ' val; printf '\n'
    else
      printf ''
      return 0
    fi
  fi
  [[ -z "${val}" ]] && printf '' && return 0
  val="$(printf '%s' "${val}" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  validate_cf_token "${val}" || die 'cf_token 格式无效。'
  printf '%s' "${val}"
}
resolve_cf_url() {
  local val="${cf_url:-}"
  if [[ -z "${val}" ]]; then
    if [[ -n "${cf_token:-}" || -n "${m_id:-}" ]]; then
      read -r -p '请输入 CF Worker 上报地址（https://...）: ' val
    else
      printf ''
      return 0
    fi
  fi
  [[ -z "${val}" ]] && printf '' && return 0
  validate_url "${val}" || die 'cf_url 须为 https:// 开头的有效 URL。'
  printf '%s' "${val}"
}
resolve_cb_port() {
  local val="${cb_port:-${CB_DEFAULT_PORT}}"
  validate_cb_port "${val}" || die "cb_port 应为 1024-65535，当前：${val}"
  printf '%s' "${val}"
}

# 显式 cb_url 优先；否则用公网 IPv4 + 端口拼 http://IP:PORT/force-report
detect_callback_url() {
  local port="$1" explicit="${cb_url:-}" ip=""
  if [[ -n "${explicit}" ]]; then
    validate_callback_url "${explicit}" || die "cb_url 无效，应为 http(s)://host:port/force-report"
    printf '%s' "${explicit}"
    return 0
  fi
  ip="$(curl -4 -fsS --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null || true)"
  if [[ -z "${ip}" ]]; then
    ip="$(curl -4 -fsS --connect-timeout 5 --max-time 10 https://ifconfig.me 2>/dev/null || true)"
  fi
  ip="$(printf '%s' "${ip}" | tr -d '[:space:]')"
  if [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    printf 'http://%s:%s/force-report' "${ip}" "${port}"
    return 0
  fi
  printf ''
  return 0
}

resolve_cf_time() {
  local val="${cf_time:-0 * * * *}"
  # 未启用 CF 时允许空/默认，不强制校验失败路径
  if [[ -z "${cf_url:-}" && -z "${cf_token:-}" && -z "${m_id:-}" ]]; then
    printf '%s' "${val}"
    return 0
  fi
  validate_cron "${val}" || die "cf_time 格式无效，应为 5 段 cron，例如：0 * * * *"
  printf '%s' "${val}"
}

# ─── cron → OnCalendar ───
cron_to_oncalendar() {
  local cron="$1" min hour dom mon dow
  set -f; set -- ${cron}; set +f
  min="$1"; hour="$2"; dom="$3"; mon="$4"; dow="$5"
  local day_part=""
  case "${dow}" in
    \*) day_part="" ;;
    0|7) day_part="Sun " ;; 1) day_part="Mon " ;; 2) day_part="Tue " ;;
    3) day_part="Wed " ;; 4) day_part="Thu " ;; 5) day_part="Fri " ;; 6) day_part="Sat " ;;
    1-5) day_part="Mon..Fri " ;;
    *) die "暂不支持的 cron 星期：${dow}" ;;
  esac
  [[ "${dom}" == "*" ]] || die "暂不支持按日 cron：${cron}"
  [[ "${mon}" == "*" ]] || die "暂不支持按月 cron：${cron}"
  local h_part m_part
  if [[ "${hour}" == "*" ]]; then h_part="*"
  elif [[ "${hour}" =~ ^\*/([0-9]+)$ ]]; then h_part="0/${BASH_REMATCH[1]}"
  elif [[ "${hour}" =~ ^[0-9]+$ ]]; then h_part="$(printf '%02d' "$((10#${hour}))")"
  elif [[ "${hour}" =~ ^([0-9]+)-([0-9]+)$ ]]; then
    h_part="$(printf '%02d' "$((10#${BASH_REMATCH[1]}))")-$(printf '%02d' "$((10#${BASH_REMATCH[2]}))")"
  else die "暂不支持 cron 小时：${hour}"; fi
  if [[ "${min}" == "*" ]]; then m_part="*"
  elif [[ "${min}" =~ ^\*/([0-9]+)$ ]]; then m_part="0/${BASH_REMATCH[1]}"
  elif [[ "${min}" =~ ^[0-9]+$ ]]; then m_part="$(printf '%02d' "$((10#${min}))")"
  else die "暂不支持 cron 分钟：${min}"; fi
  printf '%s*-*-* %s:%s:00' "${day_part}" "${h_part}" "${m_part}"
}

# ─── 安装 ───
install_deps() {
  if command -v vnstat >/dev/null 2>&1; then
    log 'vnStat 已安装，跳过安装步骤。'; VNSTAT_WAS_INSTALLED=false
  else
    VNSTAT_WAS_INSTALLED=true
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl iproute2 jq gawk
  if ${VNSTAT_WAS_INSTALLED}; then
    log '安装 vnStat...'; apt-get install -y --no-install-recommends vnstat
  fi
}

detect_interface() {
  local ifname
  ifname="$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')"
  [[ -n "${ifname}" ]] || die '未找到默认路由对应的网卡。'
  [[ "${ifname}" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || die "网卡名称异常：${ifname}"
  [[ -d "/sys/class/net/${ifname}" ]] || die "网卡不存在：${ifname}"
  printf '%s' "${ifname}"
}

configure_vnstat() {
  local ifname="$1"; log "配置 vnStat 监控网卡 ${ifname}..."
  systemctl enable --now vnstat.service
  if ! vnstat --json -i "${ifname}" >/dev/null 2>&1; then
    vnstat --add -i "${ifname}" >/dev/null 2>&1 || true
    systemctl restart vnstat.service
  fi
}

write_config() {
  local ifname="$1" m_id="$2" cf_token="$3" cf_url="$4" tg_token="$5" tg_cid="$6" cb_url="${7:-}" cb_port="${8:-}"
  local tmp; tmp="$(mktemp)"; chmod 600 "${tmp}"
  {
    printf 'INTERFACE=%s\n' "${ifname}"
    if [[ -n "${m_id}" ]]; then
      printf 'MACHINE_ID=%s\n' "${m_id}"
    fi
    if [[ -n "${cf_token}" && -n "${cf_url}" ]]; then
      # 去掉首尾空白与 \r，避免 Windows 复制/换行导致回调 Bearer 校验失败
      printf 'CF_TOKEN=%s\n' "$(printf '%s' "${cf_token}" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      printf 'CF_URL=%s\n' "$(printf '%s' "${cf_url}" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    fi
    if [[ -n "${cb_url}" ]]; then
      printf 'CALLBACK_URL=%s\n' "${cb_url}"
    fi
    if [[ -n "${cb_port}" ]]; then
      printf 'CB_PORT=%s\n' "${cb_port}"
    fi
    if [[ -n "${tg_token}" && -n "${tg_cid}" ]]; then
      printf 'TG_BOT_TOKEN=%s\n' "${tg_token}"
      printf 'TG_CHAT_ID=%s\n' "${tg_cid}"
    fi
  } >"${tmp}"
  install -o root -g root -m 600 "${tmp}" "${CONFIG_FILE}"; rm -f "${tmp}"
}

write_reporter() {
  local tmp_report; tmp_report="$(mktemp)"; chmod 600 "${tmp_report}"
  cat >"${tmp_report}" <<'REPORTER_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

readonly CONFIG="/etc/traffic-telegram-report.conf"
TG_BOT_TOKEN=""
TG_CHAT_ID=""
INTERFACE=""
CF_URL=""
CF_TOKEN=""
MACHINE_ID=""
CALLBACK_URL=""
CB_PORT="19840"

log_error() { printf '错误: %s\n' "$*" >&2; }

load_config() {
  [[ -r "${CONFIG}" ]] || { log_error "配置文件不可读：${CONFIG}"; return 1; }
  while IFS='=' read -r key val; do
    case "${key}" in
      TG_BOT_TOKEN) TG_BOT_TOKEN="${val}" ;;
      TG_CHAT_ID)   TG_CHAT_ID="${val}"   ;;
      INTERFACE)    INTERFACE="${val}"     ;;
      CF_URL)       CF_URL="${val}"        ;;
      CF_TOKEN)     CF_TOKEN="${val}"      ;;
      MACHINE_ID)   MACHINE_ID="${val}"    ;;
      CALLBACK_URL) CALLBACK_URL="${val}"  ;;
      CB_PORT)      CB_PORT="${val}"       ;;
    esac
  done <"${CONFIG}"
  [[ "${INTERFACE}" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || { log_error "INTERFACE 格式无效。"; return 1; }
}

require_cmds() {
  for cmd in awk curl date hostname jq vnstat; do
    command -v "${cmd}" >/dev/null 2>&1 || { log_error "缺少命令：${cmd}"; return 1; }
  done
}

vnstat_json() {
  local out="" i=0
  for i in 1 2 3; do
    out="$(vnstat --json -i "${INTERFACE}" 2>/dev/null)" &&
      jq -e '.interfaces[0].traffic' >/dev/null 2>&1 <<<"${out}" && {
      printf '%s' "${out}"; return 0; }
    sleep 2
  done
  log_error "无法读取网卡 ${INTERFACE} 的流量数据。"; return 1
}

extract_bytes() {
  local json="$1" period="$2" dir="$3" year="$4" month="$5" day="${6:-0}"
  jq -r --arg p "${period}" --arg d "${dir}" \
    --argjson Y "${year}" --argjson M "${month}" --argjson D "${day}" '
    .interfaces[0].traffic[$p]
    | map(select(.date.year == $Y and .date.month == $M and ($p != "day" or .date.day == $D)))
    | first | if . == null then 0 else .[$d] // 0 end
  ' <<<"${json}"
}

fmt() {
  local bytes="$1"
  [[ "${bytes}" =~ ^[0-9]+$ ]] || bytes=0
  awk -v b="${bytes}" 'BEGIN { printf "%.3fGB", b / 1000000000 }'
}

collect_stats() {
  local json year month day
  json="$(vnstat_json)"
  year="$(date '+%Y')"
  month="$((10#$(date '+%m')))"
  day="$((10#$(date '+%d')))"
  TR_RX="$(extract_bytes "${json}" day  rx "${year}" "${month}" "${day}")"
  TR_TX="$(extract_bytes "${json}" day  tx "${year}" "${month}" "${day}")"
  MR_RX="$(extract_bytes "${json}" month rx "${year}" "${month}")"
  MR_TX="$(extract_bytes "${json}" month tx "${year}" "${month}")"
  STAT_YEAR="${year}"; STAT_MONTH="${month}"; STAT_DAY="${day}"
}

# ─── TG 发送（可选） ───
send_tg() {
  local msg="$1"
  [[ -n "${TG_BOT_TOKEN}" && -n "${TG_CHAT_ID}" ]] || return 0
  [[ "${TG_BOT_TOKEN}" =~ ^[0-9]{5,20}:[A-Za-z0-9_-]{20,100}$ ]] || { log_error "TG_BOT_TOKEN 无效。"; return 1; }
  [[ "${TG_CHAT_ID}" =~ ^-?[0-9]{5,20}$ ]] || { log_error "TG_CHAT_ID 无效。"; return 1; }
  local api_url="https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage"
  local resp
  resp="$({
    printf 'url = "%s"\n' "${api_url}"
  } | curl --config - --silent --show-error --fail-with-body \
    --connect-timeout 10 --max-time 30 --retry 2 \
    --request POST \
    --data-urlencode "chat_id=${TG_CHAT_ID}" \
    --data-urlencode "text=${msg}" \
    --data "disable_web_page_preview=true")" || { log_error "Telegram API 请求失败。"; return 1; }
  jq -e '.ok == true' >/dev/null 2>&1 <<<"${resp}" || {
    log_error "Telegram 返回失败：$(jq -r '.description // "未知错误"' <<<"${resp}")"; return 1; }
}

build_tg_msg() {
  local title="${1:-流量日报}"
  printf '%s\n' "━━━━━━━━━━━━━━━━━━━━━━
${title}
━━━━━━━━━━━━━━━━━━━━━━
主机：$(hostname)
网卡：${INTERFACE}
时间：$(date '+%F %T %Z')

今日（截至发送时）
入站：$(fmt "${TR_RX}")
出站：$(fmt "${TR_TX}")
合计：$(fmt "$((TR_RX + TR_TX))")

本月（${STAT_YEAR}-$(printf '%02d' "${STAT_MONTH}")）
入站：$(fmt "${MR_RX}")
出站：$(fmt "${MR_TX}")
合计：$(fmt "$((MR_RX + MR_TX))")
━━━━━━━━━━━━━━━━━━━━━━"
}

# ─── CF 上报（可选） ───
send_cf() {
  [[ -n "${CF_URL}" && -n "${CF_TOKEN}" && -n "${MACHINE_ID}" ]] || {
    log_error "CF 未配置（需要 CF_URL / CF_TOKEN / MACHINE_ID）。"; return 1; }
  if [[ -z "${MACHINE_ID}" || ${#MACHINE_ID} -gt 64 ]]; then
    log_error "MACHINE_ID 格式无效。"; return 1
  fi
  if [[ "${MACHINE_ID}" == *[[:space:]]* || "${MACHINE_ID}" == *"'"* || "${MACHINE_ID}" == *'"'* || "${MACHINE_ID}" == */* || "${MACHINE_ID}" == *\\* ]]; then
    log_error "MACHINE_ID 格式无效。"; return 1
  fi
  [[ "${CF_TOKEN}" =~ ^[A-Za-z0-9._~+/-]{8,256}$ ]] || { log_error "CF_TOKEN 格式无效。"; return 1; }
  local payload="$(jq -nc \
    --arg m_id "${MACHINE_ID}" \
    --arg host "$(hostname)" \
    --arg iface "${INTERFACE}" \
    --arg cb "${CALLBACK_URL}" \
    --argjson ts "$(date +%s)" \
    --argjson tr_rx "${TR_RX}" \
    --argjson tr_tx "${TR_TX}" \
    --argjson mr_rx "${MR_RX}" \
    --argjson mr_tx "${MR_TX}" \
    --arg y "${STAT_YEAR}" \
    --argjson m "${STAT_MONTH}" \
    --argjson d "${STAT_DAY}" \
    '{
      machine_id: $m_id, hostname: $host, interface: $iface, ts: $ts,
      callback_url: (if $cb == "" then null else $cb end),
      date: { year: ($y|tonumber), month: $m, day: $d },
      today: { rx: $tr_rx, tx: $tr_tx, total: ($tr_rx + $tr_tx) },
      month: { rx: $mr_rx, tx: $mr_tx, total: ($mr_rx + $mr_tx) }
    }')"
  local resp
  resp="$(curl --silent --show-error --fail-with-body \
    --connect-timeout 10 --max-time 30 --retry 2 \
    --request POST \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer ${CF_TOKEN}" \
    --header "X-Machine-Id: ${MACHINE_ID}" \
    --data "${payload}" \
    "${CF_URL}")" || { log_error "CF 上报失败。"; return 1; }
  jq -e '.ok == true' >/dev/null 2>&1 <<<"${resp}" || {
    log_error "CF 返回失败：$(jq -r '.error // .message // "未知错误"' <<<"${resp}")"; return 1; }
  return 0
}

run_tg() {
  local title="流量日报"
  [[ "${1:-}" == "--test" ]] && title="[安装测试]"
  collect_stats
  send_tg "$(build_tg_msg "${title}")"
}

run_cf() {
  collect_stats
  send_cf
}

main() {
  umask 077; export LC_ALL=C
  load_config; require_cmds
  case "${1:-}" in
    --tg|--test) run_tg "${1}" ;;
    --cf)        run_cf ;;
    "")
      if [[ -n "${TG_BOT_TOKEN}" && -n "${TG_CHAT_ID}" ]]; then run_tg; fi
      if [[ -n "${CF_URL}" && -n "${CF_TOKEN}" && -n "${MACHINE_ID}" ]]; then run_cf; fi
      ;;
    *)           log_error "未知参数：${1}"; return 1 ;;
  esac
}

main "$@"
REPORTER_EOF

  install -o root -g root -m 750 "${tmp_report}" "${REPORT_SCRIPT}"
  rm -f "${tmp_report}"
}

write_callback_listener() {
  local port="$1"
  local tmp; tmp="$(mktemp)"; chmod 600 "${tmp}"
  # shellcheck disable=SC2001
  base64 -d >"${tmp}" <<'B64'
IyEvdXNyL2Jpbi9lbnYgYmFzaAojIOacrOacuuWbnuiwg++8muS7heaOpeWPl+W4piBITUFDIOet
vuWQjeeahCBmb3JjZS1yZXBvcnTvvIzop6blj5Hnq4vljbMgQ0Yg5LiK5oqlCnNldCAtRWV1byBw
aXBlZmFpbApyZWFkb25seSBDT05GSUc9Ii9ldGMvdHJhZmZpYy10ZWxlZ3JhbS1yZXBvcnQuY29u
ZiIKcmVhZG9ubHkgUkVQT1JUPSIvdXNyL2xvY2FsL3NiaW4vdHJhZmZpYy10ZWxlZ3JhbS1yZXBv
cnQiCnJlYWRvbmx5IE5PTkNFX0RJUj0iL3J1bi90cmFmZmljLXRlbGVncmFtLXJlcG9ydC1ub25j
ZXMiCkNGX1RPS0VOPSIiCkNCX1BPUlQ9IjE5ODQwIgoKbG9hZF90b2tlbigpIHsKICBbWyAtciAi
JHtDT05GSUd9IiBdXSB8fCBleGl0IDEKICB3aGlsZSBJRlM9IHJlYWQgLXIgbGluZSB8fCBbWyAt
biAiJHtsaW5lfSIgXV07IGRvCiAgICBsaW5lPSIke2xpbmUvLyQnXHInL30iCiAgICBbWyAteiAi
JHtsaW5lfSIgfHwgIiR7bGluZX0iID1+IF5bWzpzcGFjZTpdXSojIF1dICYmIGNvbnRpbnVlCiAg
ICBrZXk9IiR7bGluZSUlPSp9IgogICAgdmFsPSIke2xpbmUjKj19IgogICAga2V5PSIkKHByaW50
ZiAnJXMnICIke2tleX0iIHwgc2VkICdzL15bWzpzcGFjZTpdXSovLztzL1tbOnNwYWNlOl1dKiQv
LycpIgogICAgdmFsPSIkKHByaW50ZiAnJXMnICIke3ZhbH0iIHwgc2VkICdzL15bWzpzcGFjZTpd
XSovLztzL1tbOnNwYWNlOl1dKiQvLycpIgogICAgY2FzZSAiJHtrZXl9IiBpbgogICAgICBDRl9U
T0tFTikgQ0ZfVE9LRU49IiR7dmFsfSIgOzsKICAgICAgQ0JfUE9SVCkgIENCX1BPUlQ9IiR7dmFs
fSIgOzsKICAgIGVzYWMKICBkb25lIDwiJHtDT05GSUd9IgogIFtbIC1uICIke0NGX1RPS0VOfSIg
XV0gfHwgZXhpdCAxCn0KCm1haW4oKSB7CiAgbG9hZF90b2tlbgogIGxvY2FsIHBvcnQ9IiR7MTot
JHtDQl9QT1JUfX0iCiAgY29tbWFuZCAtdiBweXRob24zID4vZGV2L251bGwgMj4mMSB8fCB7IGVj
aG8gIumcgOimgSBweXRob24zIiA+JjI7IGV4aXQgMTsgfQogIGV4ZWMgcHl0aG9uMyAtICIke3Bv
cnR9IiAiJHtDRl9UT0tFTn0iIDw8J1BZSU5ORVInCmltcG9ydCBoYXNobGliLCBobWFjLCBvcywg
cmUsIHNvY2tldCwgc3VicHJvY2Vzcywgc3lzLCB0aW1lCmZyb20gcGF0aGxpYiBpbXBvcnQgUGF0
aAoKUkVQT1JUID0gIi91c3IvbG9jYWwvc2Jpbi90cmFmZmljLXRlbGVncmFtLXJlcG9ydCIKTk9O
Q0VfRElSID0gUGF0aCgiL3J1bi90cmFmZmljLXRlbGVncmFtLXJlcG9ydC1ub25jZXMiKQpwb3J0
ID0gaW50KHN5cy5hcmd2WzFdKQp0b2tlbiA9IHN5cy5hcmd2WzJdLnN0cmlwKCkucmVwbGFjZSgi
XHIiLCAiIikucmVwbGFjZSgiXG4iLCAiIikKCmRlZiBsb2cobXNnOiBzdHIpIC0+IE5vbmU6CiAg
ICB0cnk6CiAgICAgICAgc3lzLnN0ZGVyci53cml0ZSh0aW1lLnN0cmZ0aW1lKCIlWS0lbS0lZCAl
SDolTTolUyAiKSArIG1zZyArICJcbiIpCiAgICAgICAgc3lzLnN0ZGVyci5mbHVzaCgpCiAgICBl
eGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHBhc3MKCmRlZiBzZWVuX25vbmNlKG46IHN0cikgLT4g
Ym9vbDoKICAgIE5PTkNFX0RJUi5ta2RpcihwYXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpCiAg
ICBub3cgPSB0aW1lLnRpbWUoKQogICAgZm9yIGYgaW4gbGlzdChOT05DRV9ESVIuaXRlcmRpcigp
KToKICAgICAgICB0cnk6CiAgICAgICAgICAgIGlmIG5vdyAtIGYuc3RhdCgpLnN0X210aW1lID4g
MzAwOgogICAgICAgICAgICAgICAgZi51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgICAgIGV4
Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIHBhc3MKICAgIHAgPSBOT05DRV9ESVIgLyBuCiAg
ICBpZiBwLmV4aXN0cygpOgogICAgICAgIHJldHVybiBUcnVlCiAgICBwLndyaXRlX3RleHQoIjEi
KQogICAgcmV0dXJuIEZhbHNlCgpkZWYgc2VuZF9yZXNwKGNvbm4sIGNvZGU6IHN0ciwgbXNnOiBz
dHIpIC0+IE5vbmU6CiAgICBiID0gbXNnLmVuY29kZSgpCiAgICB0cnk6CiAgICAgICAgY29ubi5z
ZW5kYWxsKAogICAgICAgICAgICAoCiAgICAgICAgICAgICAgICBmIkhUVFAvMS4xIHtjb2RlfVxy
XG4iCiAgICAgICAgICAgICAgICBmIkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG4i
CiAgICAgICAgICAgICAgICBmIkNvbm5lY3Rpb246IGNsb3NlXHJcbiIKICAgICAgICAgICAgICAg
IGYiQ29udGVudC1MZW5ndGg6IHtsZW4oYil9XHJcbiIKICAgICAgICAgICAgICAgIGYiXHJcbiIK
ICAgICAgICAgICAgKS5lbmNvZGUoKQogICAgICAgICAgICArIGIKICAgICAgICApCiAgICBleGNl
cHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgbG9nKCJzZW5kX3Jlc3AgZmFpbGVkOiAiICsgc3Ry
KGUpKQoKZGVmIHJlY3ZfYWxsX2hlYWRlcnMoY29ubiwgbGltaXQ9MTYzODQpOgogICAgZGF0YSA9
IGIiIgogICAgd2hpbGUgYiJcclxuXHJcbiIgbm90IGluIGRhdGEgYW5kIGxlbihkYXRhKSA8IGxp
bWl0OgogICAgICAgIHRyeToKICAgICAgICAgICAgY2h1bmsgPSBjb25uLnJlY3YoNDA5NikKICAg
ICAgICBleGNlcHQgc29ja2V0LnRpbWVvdXQ6CiAgICAgICAgICAgIGJyZWFrCiAgICAgICAgaWYg
bm90IGNodW5rOgogICAgICAgICAgICBicmVhawogICAgICAgIGRhdGEgKz0gY2h1bmsKICAgIHJl
dHVybiBkYXRhCgpkZWYgaGFuZGxlKGNvbm4sIHRva2VuOiBzdHIpIC0+IE5vbmU6CiAgICBjb25u
LnNldHRpbWVvdXQoMTUpCiAgICBkYXRhID0gcmVjdl9hbGxfaGVhZGVycyhjb25uKQogICAgaWYg
YiJcclxuXHJcbiIgbm90IGluIGRhdGE6CiAgICAgICAgc2VuZF9yZXNwKGNvbm4sICI0MDAgQmFk
IFJlcXVlc3QiLCAneyJvayI6ZmFsc2UsImVycm9yIjoiaW5jb21wbGV0ZSByZXF1ZXN0In0nKQog
ICAgICAgIGxvZygiaW5jb21wbGV0ZSByZXF1ZXN0IGxlbj0iICsgc3RyKGxlbihkYXRhKSkpCiAg
ICAgICAgcmV0dXJuCiAgICBoZWFkLCBfLCByZXN0ID0gZGF0YS5wYXJ0aXRpb24oYiJcclxuXHJc
biIpCiAgICBsaW5lcyA9IGhlYWQuZGVjb2RlKCJsYXRpbjEiLCAicmVwbGFjZSIpLnNwbGl0KCJc
clxuIikKICAgIHJlcSA9IGxpbmVzWzBdLnNwbGl0KCkKICAgIGlmIGxlbihyZXEpIDwgMjoKICAg
ICAgICBzZW5kX3Jlc3AoY29ubiwgIjQwMCBCYWQgUmVxdWVzdCIsICd7Im9rIjpmYWxzZSwiZXJy
b3IiOiJiYWQgcmVxdWVzdCBsaW5lIn0nKQogICAgICAgIHJldHVybgogICAgbWV0aG9kLCBwYXRo
ID0gcmVxWzBdLCByZXFbMV0KICAgIGhlYWRlcnMgPSB7fQogICAgZm9yIGxpbmUgaW4gbGluZXNb
MTpdOgogICAgICAgIGlmICI6IiBpbiBsaW5lOgogICAgICAgICAgICBrLCB2ID0gbGluZS5zcGxp
dCgiOiIsIDEpCiAgICAgICAgICAgIGhlYWRlcnNbay5zdHJpcCgpLmxvd2VyKCldID0gdi5zdHJp
cCgpCiAgICB0cnk6CiAgICAgICAgY2xlbiA9IGludChoZWFkZXJzLmdldCgiY29udGVudC1sZW5n
dGgiKSBvciAwKQogICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgY2xlbiA9IDAKICAgIGlm
IGNsZW4gPCAwIG9yIGNsZW4gPiA0MDk2OgogICAgICAgIHNlbmRfcmVzcChjb25uLCAiNDAwIEJh
ZCBSZXF1ZXN0IiwgJ3sib2siOmZhbHNlLCJlcnJvciI6ImJhZCBjb250ZW50LWxlbmd0aCJ9JykK
ICAgICAgICByZXR1cm4KICAgIGJvZHkgPSByZXN0CiAgICB3aGlsZSBsZW4oYm9keSkgPCBjbGVu
OgogICAgICAgIHRyeToKICAgICAgICAgICAgY2h1bmsgPSBjb25uLnJlY3YoY2xlbiAtIGxlbihi
b2R5KSkKICAgICAgICBleGNlcHQgc29ja2V0LnRpbWVvdXQ6CiAgICAgICAgICAgIGJyZWFrCiAg
ICAgICAgaWYgbm90IGNodW5rOgogICAgICAgICAgICBicmVhawogICAgICAgIGJvZHkgKz0gY2h1
bmsKICAgIGJvZHkgPSBib2R5WzpjbGVuXQoKICAgIGlmIG1ldGhvZCAhPSAiUE9TVCIgb3IgcGF0
aCAhPSAiL2ZvcmNlLXJlcG9ydCI6CiAgICAgICAgc2VuZF9yZXNwKGNvbm4sICI0MDQgTm90IEZv
dW5kIiwgJ3sib2siOmZhbHNlLCJlcnJvciI6Im5vdCBmb3VuZCJ9JykKICAgICAgICByZXR1cm4K
CiAgICBhdXRoID0gaGVhZGVycy5nZXQoImF1dGhvcml6YXRpb24iLCAiIikKICAgIGlmIGF1dGgu
bG93ZXIoKS5zdGFydHN3aXRoKCJiZWFyZXIgIik6CiAgICAgICAgYXV0aCA9IGF1dGhbNzpdLnN0
cmlwKCkKICAgIGF1dGggPSBhdXRoLnJlcGxhY2UoIlxyIiwgIiIpLnJlcGxhY2UoIlxuIiwgIiIp
LnN0cmlwKCkKICAgICMg6K+K5pat77ya6ZW/5bqm5LiN5LiA6Ie05pe255u05o6l6K+05piO77yM
6YG/5YWN56y857ufIHVuYXV0aG9yaXplZAogICAgaWYgbm90IGF1dGg6CiAgICAgICAgc2VuZF9y
ZXNwKGNvbm4sICI0MDEgVW5hdXRob3JpemVkIiwgJ3sib2siOmZhbHNlLCJlcnJvciI6Im1pc3Np
bmcgYmVhcmVyIn0nKQogICAgICAgIGxvZygiYXV0aCBtaXNzaW5nIGJlYXJlciIpCiAgICAgICAg
cmV0dXJuCiAgICBpZiBsZW4oYXV0aCkgIT0gbGVuKHRva2VuKToKICAgICAgICBzZW5kX3Jlc3Ao
CiAgICAgICAgICAgIGNvbm4sCiAgICAgICAgICAgICI0MDEgVW5hdXRob3JpemVkIiwKICAgICAg
ICAgICAgJ3sib2siOmZhbHNlLCJlcnJvciI6InRva2VuIGxlbmd0aCBtaXNtYXRjaCBnb3Q9JWQg
ZXhwZWN0PSVkIn0nCiAgICAgICAgICAgICUgKGxlbihhdXRoKSwgbGVuKHRva2VuKSksCiAgICAg
ICAgKQogICAgICAgIGxvZygiYXV0aCBsZW4gbWlzbWF0Y2ggZ290PSVkIGV4cGVjdD0lZCIgJSAo
bGVuKGF1dGgpLCBsZW4odG9rZW4pKSkKICAgICAgICByZXR1cm4KICAgIGlmIG5vdCBobWFjLmNv
bXBhcmVfZGlnZXN0KGF1dGgsIHRva2VuKToKICAgICAgICBzZW5kX3Jlc3AoY29ubiwgIjQwMSBV
bmF1dGhvcml6ZWQiLCAneyJvayI6ZmFsc2UsImVycm9yIjoidG9rZW4gbWlzbWF0Y2gifScpCiAg
ICAgICAgbG9nKCJhdXRoIHRva2VuIG1pc21hdGNoIChzYW1lIGxlbmd0aCkiKQogICAgICAgIHJl
dHVybgoKICAgIHRzID0gaGVhZGVycy5nZXQoIngtdGltZXN0YW1wIiwgIiIpCiAgICBub25jZSA9
IGhlYWRlcnMuZ2V0KCJ4LW5vbmNlIiwgIiIpCiAgICBzaWcgPSBoZWFkZXJzLmdldCgieC1zaWdu
YXR1cmUiLCAiIikubG93ZXIoKS5zdHJpcCgpCiAgICBpZiBub3QgcmUuZnVsbG1hdGNoKHIiWzAt
OV0rIiwgdHMpOgogICAgICAgIHNlbmRfcmVzcChjb25uLCAiNDAxIFVuYXV0aG9yaXplZCIsICd7
Im9rIjpmYWxzZSwiZXJyb3IiOiJiYWQgdGltZXN0YW1wIn0nKQogICAgICAgIHJldHVybgogICAg
aWYgYWJzKGludCh0aW1lLnRpbWUoKSkgLSBpbnQodHMpKSA+IDEyMDoKICAgICAgICBzZW5kX3Jl
c3AoY29ubiwgIjQwMSBVbmF1dGhvcml6ZWQiLCAneyJvayI6ZmFsc2UsImVycm9yIjoidGltZXN0
YW1wIGV4cGlyZWQifScpCiAgICAgICAgcmV0dXJuCiAgICBpZiBub3QgcmUuZnVsbG1hdGNoKHIi
W0EtWmEtejAtOS5fLV17OCw2NH0iLCBub25jZSk6CiAgICAgICAgc2VuZF9yZXNwKGNvbm4sICI0
MDEgVW5hdXRob3JpemVkIiwgJ3sib2siOmZhbHNlLCJlcnJvciI6ImJhZCBub25jZSJ9JykKICAg
ICAgICByZXR1cm4KICAgIGlmIHNlZW5fbm9uY2Uobm9uY2UpOgogICAgICAgIHNlbmRfcmVzcChj
b25uLCAiNDAxIFVuYXV0aG9yaXplZCIsICd7Im9rIjpmYWxzZSwiZXJyb3IiOiJub25jZSByZXVz
ZWQifScpCiAgICAgICAgcmV0dXJuCgogICAgbXNnID0gZiJ7dHN9XG57bm9uY2V9XG4iLmVuY29k
ZSgpICsgYm9keQogICAgZXhwZWN0ID0gaG1hYy5uZXcodG9rZW4uZW5jb2RlKCJ1dGYtOCIpLCBt
c2csIGhhc2hsaWIuc2hhMjU2KS5oZXhkaWdlc3QoKQogICAgaWYgbm90IGhtYWMuY29tcGFyZV9k
aWdlc3QoZXhwZWN0LCBzaWcpOgogICAgICAgIHNlbmRfcmVzcChjb25uLCAiNDAxIFVuYXV0aG9y
aXplZCIsICd7Im9rIjpmYWxzZSwiZXJyb3IiOiJiYWQgc2lnbmF0dXJlIn0nKQogICAgICAgIGxv
ZygiYmFkIHNpZ25hdHVyZSIpCiAgICAgICAgcmV0dXJuCgogICAgc2VuZF9yZXNwKGNvbm4sICIy
MDAgT0siLCAneyJvayI6dHJ1ZSwiYWNjZXB0ZWQiOnRydWV9JykKICAgIHRyeToKICAgICAgICBz
dWJwcm9jZXNzLlBvcGVuKAogICAgICAgICAgICBbUkVQT1JULCAiLS1jZiJdLAogICAgICAgICAg
ICBzdGRvdXQ9c3VicHJvY2Vzcy5ERVZOVUxMLAogICAgICAgICAgICBzdGRlcnI9c3VicHJvY2Vz
cy5ERVZOVUxMLAogICAgICAgICAgICBzdGFydF9uZXdfc2Vzc2lvbj1UcnVlLAogICAgICAgICkK
ICAgICAgICBsb2coImFjY2VwdGVkIGZvcmNlLXJlcG9ydCwgc3Bhd25lZCAtLWNmIikKICAgIGV4
Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICBsb2coInNwYXduIHJlcG9ydCBmYWlsZWQ6ICIg
KyBzdHIoZSkpCgpzcnYgPSBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULCBzb2NrZXQuU09D
S19TVFJFQU0pCnNydi5zZXRzb2Nrb3B0KHNvY2tldC5TT0xfU09DS0VULCBzb2NrZXQuU09fUkVV
U0VBRERSLCAxKQpzcnYuYmluZCgoIjAuMC4wLjAiLCBwb3J0KSkKc3J2Lmxpc3RlbigzMikKbG9n
KCJjYWxsYmFjayBsaXN0ZW5pbmcgdG9rZW5fbGVuPSVkIHBvcnQ9JWQiICUgKGxlbih0b2tlbiks
IHBvcnQpKQp3aGlsZSBUcnVlOgogICAgY29ubiwgYWRkciA9IHNydi5hY2NlcHQoKQogICAgdHJ5
OgogICAgICAgIGhhbmRsZShjb25uLCB0b2tlbikKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToK
ICAgICAgICBsb2coImhhbmRsZSBlcnJvciBmcm9tICVzOiAlcyIgJSAoYWRkciwgZSkpCiAgICAg
ICAgdHJ5OgogICAgICAgICAgICBzZW5kX3Jlc3AoY29ubiwgIjUwMCBJbnRlcm5hbCBTZXJ2ZXIg
RXJyb3IiLCAneyJvayI6ZmFsc2UsImVycm9yIjoiaW50ZXJuYWwifScpCiAgICAgICAgZXhjZXB0
IEV4Y2VwdGlvbjoKICAgICAgICAgICAgcGFzcwogICAgZmluYWxseToKICAgICAgICB0cnk6CiAg
ICAgICAgICAgIGNvbm4uc2h1dGRvd24oc29ja2V0LlNIVVRfUkRXUikKICAgICAgICBleGNlcHQg
RXhjZXB0aW9uOgogICAgICAgICAgICBwYXNzCiAgICAgICAgdHJ5OgogICAgICAgICAgICBjb25u
LmNsb3NlKCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICBwYXNzClBZSU5O
RVIKfQoKbWFpbiAiJEAiCg==
B64
  install -o root -g root -m 750 "${tmp}" "${CB_LISTEN_SCRIPT}"
  rm -f "${tmp}"

  cat >"${CB_SERVICE_FILE}" <<SERVICE_EOF
[Unit]
Description=Accept signed force-report callbacks for traffic agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${CB_LISTEN_SCRIPT} ${port}
Restart=on-failure
RestartSec=3
User=root
Group=root
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/run
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
SERVICE_EOF
}

# ─── systemd 单元 ───
write_service_unit() {
  local exec_flag="$1"
  cat >"${SERVICE_FILE}" <<SERVICE_EOF
[Unit]
Description=Send vnStat traffic report to Telegram
After=network-online.target vnstat.service
Wants=network-online.target vnstat.service

[Service]
Type=oneshot
ExecStart=${REPORT_SCRIPT} ${exec_flag}
User=root; Group=root; UMask=0077
NoNewPrivileges=true; PrivateDevices=true; PrivateTmp=true
ProtectKernelModules=true; ProtectKernelTunables=true
ProtectSystem=strict; RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
SERVICE_EOF
}

write_cf_service_unit() {
  cat >"${CF_SERVICE_FILE}" <<SERVICE_EOF
[Unit]
Description=Send vnStat traffic to Cloudflare Worker
After=network-online.target vnstat.service
Wants=network-online.target vnstat.service

[Service]
Type=oneshot
ExecStart=${REPORT_SCRIPT} --cf
User=root; Group=root; UMask=0077
NoNewPrivileges=true; PrivateDevices=true; PrivateTmp=true
ProtectKernelModules=true; ProtectKernelTunables=true
ProtectSystem=strict; RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
SERVICE_EOF
}

write_tg_timer() {
  local report_time="$1"
  cat >"${TIMER_FILE}" <<TIMER_EOF
[Unit]
Description=Telegram traffic report daily at ${report_time}
[Timer]
OnCalendar=*-*-* ${report_time}
Persistent=true; AccuracySec=1min; Unit=${APP_NAME}.service
[Install]
WantedBy=timers.target
TIMER_EOF
}

write_cf_timer() {
  local cron_expr="$1"
  local oncal; oncal="$(cron_to_oncalendar "${cron_expr}")"
  log "CF 调度 cron「${cron_expr}」→ OnCalendar「${oncal}」"
  cat >"${CF_TIMER_FILE}" <<TIMER_EOF
[Unit]
Description=Cloudflare traffic report (${cron_expr})
[Timer]
OnCalendar=${oncal}
OnBootSec=30
Persistent=true; AccuracySec=1min; Unit=${APP_NAME}-cf.service
[Install]
WantedBy=timers.target
TIMER_EOF
}


enable_timers() {
  local tg_enabled="$1" cf_enabled="$2"
  systemctl daemon-reload
  if [[ "${cf_enabled}" == "1" ]]; then
    systemctl enable --now "${APP_NAME}-cf.timer"
    systemctl enable --now "${APP_NAME}-cb.service"
    # 不再安装 poll；清理旧版 poll timer（若曾装过）
    systemctl disable --now "${APP_NAME}-poll.timer" >/dev/null 2>&1 || true
    rm -f "${CF_POLL_SERVICE_FILE}" "${CF_POLL_TIMER_FILE}"
  else
    systemctl disable --now "${APP_NAME}-cf.timer" >/dev/null 2>&1 || true
    systemctl disable --now "${APP_NAME}-poll.timer" >/dev/null 2>&1 || true
    systemctl disable --now "${APP_NAME}-cb.service" >/dev/null 2>&1 || true
    rm -f "${CF_SERVICE_FILE}" "${CF_TIMER_FILE}" "${CF_POLL_SERVICE_FILE}" "${CF_POLL_TIMER_FILE}"       "${CB_SERVICE_FILE}" "${CB_LISTEN_SCRIPT}"
  fi
  if [[ "${tg_enabled}" == "1" ]]; then
    systemctl enable --now "${APP_NAME}.timer"
  else
    systemctl disable --now "${APP_NAME}.timer" >/dev/null 2>&1 || true
    rm -f "${SERVICE_FILE}" "${TIMER_FILE}"
  fi
  systemctl daemon-reload
}

send_test() {
  if [[ "${CF_ENABLED}" == "true" ]]; then
    log '安装完成，立即上报一次 CF 流量...'
    "${REPORT_SCRIPT}" --cf || die 'CF 立即上报失败。请检查 cf_url / cf_token / m_id。'
  fi
  if [[ "${TG_ENABLED}" == "true" ]]; then
    log '发送 Telegram 测试消息...'
    "${REPORT_SCRIPT}" --test || die 'Telegram 测试发送失败。'
  fi
}

print_summary() {
  local ifname="$1" tg_time="$2" cf_cron="$3" m_id="$4"
  printf '\n安装完成。\n'
  printf '  监控网卡：  %s\n'   "${ifname}"
  if [[ "${CF_ENABLED}" == "true" ]]; then
    printf '  机器 ID：    %s\n'   "${m_id}"
    printf '  CF 上报：    cron %s\n' "${cf_cron}"
  else
    printf '  CF 上报：    未启用（设置 cf_url+cf_token+m_id 可开启）\n'
  fi
  if [[ "${TG_ENABLED}" == "true" ]]; then
    printf '  TG 汇报：    每天 %s\n' "${tg_time}"
  else
    printf '  TG 汇报：    未启用（设置 t_token+t_id 可开启）\n'
  fi
  printf '  配置文件：   %s（仅 root 可读）\n' "${CONFIG_FILE}"
  if [[ "${CF_ENABLED}" == "true" ]]; then
    printf '  立即 CF 上报：systemctl start %s-cf.service\n' "${APP_NAME}"
    printf '  回调推送：  看板「获取流量」→ Worker 签名请求本机 /force-report\n'
    printf '  回调服务：  systemctl status %s-cb.service\n' "${APP_NAME}"
    printf '  查看日志：   journalctl -u %s-cf.service\n' "${APP_NAME}"
  fi
  if [[ "${TG_ENABLED}" == "true" ]]; then
    printf '  立即 TG 发送：systemctl start %s.service\n' "${APP_NAME}"
    printf '  查看日志：   journalctl -u %s.service\n' "${APP_NAME}"
  fi
  printf '  卸载：       bash $0 --uninstall\n'
  if ${VNSTAT_WAS_INSTALLED}; then
    printf '\n注意：vnStat 是本次新安装，只能统计安装后的流量。\n'
  else
    printf '\nvnStat 已存在，流量数据包含之前的统计记录。\n'
  fi
}

uninstall_app() {
  systemctl disable --now "${APP_NAME}.timer" >/dev/null 2>&1 || true
  systemctl disable --now "${APP_NAME}-cf.timer" >/dev/null 2>&1 || true
  systemctl disable --now "${APP_NAME}-poll.timer" >/dev/null 2>&1 || true
  systemctl disable --now "${APP_NAME}-cb.service" >/dev/null 2>&1 || true
  rm -f "${REPORT_SCRIPT}" "${CONFIG_FILE}" \
    "${SERVICE_FILE}" "${TIMER_FILE}" \
    "${CF_SERVICE_FILE}" "${CF_TIMER_FILE}" \
    "${CF_POLL_SERVICE_FILE}" "${CF_POLL_TIMER_FILE}" \
    "${CB_SERVICE_FILE}" "${CB_LISTEN_SCRIPT}"
  systemctl daemon-reload; systemctl reset-failed >/dev/null 2>&1 || true
  log '已卸载流量汇报服务；vnStat 软件及数据库未删除。'
}

main() {
  # 注意：不可 local m_id/cf_token/cf_url，会遮蔽命令行传入的环境变量
  local ifname mid_val cf_token_val cf_url_val tg_token tg_cid tg_time cf_cron
  require_root
  if [[ "${1:-}" == '--uninstall' ]]; then uninstall_app; return; fi
  check_debian13

  # 解析参数（resolve_* 读取环境变量 t_token/m_id/cf_* 等）
  tg_token="$(resolve_t_token)"
  tg_cid="$(resolve_t_id)"
  tg_time="$(resolve_t_time)"
  if [[ -n "${tg_token}" && -n "${tg_cid}" ]]; then
    TG_ENABLED=true
  fi
  mid_val="$(resolve_m_id)"
  cf_token_val="$(resolve_cf_token)"
  cf_url_val="$(resolve_cf_url)"
  cf_cron="$(resolve_cf_time)"
  local cb_port_val="" cb_url_val=""
  if [[ -n "${cf_url_val}" && -n "${cf_token_val}" && -n "${mid_val}" ]]; then
    CF_ENABLED=true
    cb_port_val="$(resolve_cb_port)"
    cb_url_val="$(detect_callback_url "${cb_port_val}")"
    if [[ -z "${cb_url_val}" ]]; then
      log "警告: 未能自动检测公网 IP，看板即时推送将不可用。可设置 cb_url=http://IP:端口/force-report 并放行防火墙"
    else
      log "回调地址: ${cb_url_val}"
    fi
  fi

  # 至少启用一条通道
  if [[ "${TG_ENABLED}" != "true" && "${CF_ENABLED}" != "true" ]]; then
    die '请至少配置 TG（t_token+t_id）或 CF（cf_url+cf_token+m_id）其中一组。'
  fi

  install_deps
  if [[ "${CF_ENABLED}" == "true" ]]; then
    if ! command -v python3 >/dev/null 2>&1; then
      apt-get install -y --no-install-recommends python3 || log "警告: 未安装 python3，回调监听可能无法启动"
    fi
  fi
  ifname="$(detect_interface)"
  configure_vnstat "${ifname}"
  write_config "${ifname}" "${mid_val}" "${cf_token_val}" "${cf_url_val}" "${tg_token}" "${tg_cid}" "${cb_url_val}" "${cb_port_val}"
  write_reporter

  # CF 服务/定时（可选）
  if [[ "${CF_ENABLED}" == "true" ]]; then
    write_cf_service_unit
    write_cf_timer "${cf_cron}"
    write_callback_listener "${cb_port_val:-$CB_DEFAULT_PORT}"
  fi

  # TG 服务/定时（可选）
  if [[ "${TG_ENABLED}" == "true" ]]; then
    write_service_unit "--tg"
    write_tg_timer "${tg_time}"
  fi

  enable_timers \
    "$( [[ "${TG_ENABLED}" == "true" ]] && printf 1 || printf 0 )" \
    "$( [[ "${CF_ENABLED}" == "true" ]] && printf 1 || printf 0 )"
  send_test
  print_summary "${ifname}" "${tg_time}" "${cf_cron}" "${mid_val}"
}

main "$@"
