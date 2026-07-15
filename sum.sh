#!/usr/bin/env bash
set -Eeuo pipefail

readonly APP_NAME="traffic-telegram-report"
readonly REPORT_SCRIPT="/usr/local/sbin/${APP_NAME}"
readonly CONFIG_FILE="/etc/${APP_NAME}.conf"
readonly SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
readonly TIMER_FILE="/etc/systemd/system/${APP_NAME}.timer"

VNSTAT_WAS_INSTALLED=false

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

validate_token() { [[ "$1" =~ ^[0-9]{5,20}:[A-Za-z0-9_-]{20,100}$ ]]; }
validate_chat_id() { [[ "$1" =~ ^-?[0-9]{5,20}$ ]]; }

resolve_token() {
  local val="${ttoken:-}"
  if [[ -z "${val}" ]]; then
    read -r -s -p '请输入 Telegram Bot Token: ' val; printf '\n'
  fi
  validate_token "${val}" || die 'Bot Token 格式无效。'
  printf '%s' "${val}"
}

resolve_chat_id() {
  local val="${tid:-}"
  if [[ -z "${val}" ]]; then
    read -r -p '请输入 Telegram Chat ID: ' val
  fi
  validate_chat_id "${val}" || die 'Chat ID 应为纯数字，可带负号。'
  printf '%s' "${val}"
}

install_deps() {
  if command -v vnstat >/dev/null 2>&1; then
    log 'vnStat 已安装，跳过安装步骤。'
    VNSTAT_WAS_INSTALLED=false
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
  # 幂等：仅当该网卡尚未被 vnStat 监控时才添加，避免重复安装报错
  if ! vnstat --json -i "${ifname}" >/dev/null 2>&1; then
    vnstat --add -i "${ifname}" >/dev/null 2>&1 || true
    systemctl restart vnstat.service
  fi
}

write_config() {
  local ifname="$1" token="$2" chat_id="$3"
  local tmp
  tmp="$(mktemp)"; chmod 600 "${tmp}"
  printf 'TG_BOT_TOKEN=%s\nTG_CHAT_ID=%s\nINTERFACE=%s\n' \
    "${token}" "${chat_id}" "${ifname}" >"${tmp}"
  install -o root -g root -m 600 "${tmp}" "${CONFIG_FILE}"; rm -f "${tmp}"
}

write_reporter() {
  local tmp_report
  tmp_report="$(mktemp)"; chmod 600 "${tmp_report}"
  cat >"${tmp_report}" <<'REPORTER_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

readonly CONFIG="/etc/traffic-telegram-report.conf"
TG_BOT_TOKEN=""
TG_CHAT_ID=""
INTERFACE=""

log_error()  { printf '错误: %s\n' "$*" >&2; }

load_config() {
  [[ -r "${CONFIG}" ]] || { log_error "配置文件不可读：${CONFIG}"; return 1; }
  while IFS='=' read -r key val; do
    case "${key}" in
      TG_BOT_TOKEN) TG_BOT_TOKEN="${val}" ;;
      TG_CHAT_ID)   TG_CHAT_ID="${val}"   ;;
      INTERFACE)    INTERFACE="${val}"     ;;
    esac
  done <"${CONFIG}"
  [[ "${TG_BOT_TOKEN}" =~ ^[0-9]{5,20}:[A-Za-z0-9_-]{20,100}$ ]] || { log_error "TG_BOT_TOKEN 格式无效。"; return 1; }
  [[ "${TG_CHAT_ID}" =~ ^-?[0-9]{5,20}$ ]] || { log_error "TG_CHAT_ID 格式无效。"; return 1; }
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
  log_error "无法读取网卡 ${INTERFACE} 的流量数据。"
  return 1
}

extract_bytes() {
  local json="$1" period="$2" dir="$3" year="$4" month="$5" day="${6:-0}"
  jq -r --arg p "${period}" --arg d "${dir}" \
    --argjson Y "${year}" --argjson M "${month}" --argjson D "${day}" '
    .interfaces[0].traffic[$p]
    | map(select(
        .date.year == $Y
        and .date.month == $M
        and ($p != "day" or .date.day == $D)
      ))
    | first
    | if . == null then 0 else .[$d] // 0 end
  ' <<<"${json}"
}

fmt() {
  # 统一按 GB 显示（1GB=1000^3 字节），保留 3 位小数，如 1MB -> 0.001GB
  local bytes="$1"
  [[ "${bytes}" =~ ^[0-9]+$ ]] || bytes=0
  awk -v b="${bytes}" 'BEGIN { printf "%.3fGB", b / 1000000000 }'
}

send_tg() {
  local msg="$1" api_url="" resp=""
  api_url="https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage"
  resp="$({
    printf 'url = "%s"\n' "${api_url}"
  } | curl --config - --silent --show-error --fail-with-body \
    --connect-timeout 10 --max-time 30 --retry 2 \
    --request POST \
    --data-urlencode "chat_id=${TG_CHAT_ID}" \
    --data-urlencode "text=${msg}" \
    --data "disable_web_page_preview=true")" || {
    log_error "Telegram API 请求失败。"; return 1; }
  jq -e '.ok == true' >/dev/null 2>&1 <<<"${resp}" || {
    log_error "Telegram 返回失败：$(jq -r '.description // "未知错误"' <<<"${resp}")"
    return 1
  }
}

build_and_send() {
  local json="" year="" month="" day=""
  local tr_rx=0 tr_tx=0 mr_rx=0 mr_tx=0
  local title="流量日报"
  local msg=""

  json="$(vnstat_json)"
  year="$(date '+%Y')"
  month="$((10#$(date '+%m')))"
  day="$((10#$(date '+%d')))"

  tr_rx="$(extract_bytes "${json}" day  rx "${year}" "${month}" "${day}")"
  tr_tx="$(extract_bytes "${json}" day  tx "${year}" "${month}" "${day}")"
  mr_rx="$(extract_bytes "${json}" month rx "${year}" "${month}")"
  mr_tx="$(extract_bytes "${json}" month tx "${year}" "${month}")"

  [[ "${1:-}" == "--test" ]] && title="[安装测试]"

  msg="━━━━━━━━━━━━━━━━━━━━━━
${title}
━━━━━━━━━━━━━━━━━━━━━━
主机：$(hostname)
网卡：${INTERFACE}
时间：$(date '+%F %T %Z')

今日（截至发送时）
入站：$(fmt "${tr_rx}")
出站：$(fmt "${tr_tx}")
合计：$(fmt "$((tr_rx + tr_tx))")

本月（${year}-$(printf '%02d' "${month}")）
入站：$(fmt "${mr_rx}")
出站：$(fmt "${mr_tx}")
合计：$(fmt "$((mr_rx + mr_tx))")
━━━━━━━━━━━━━━━━━━━━━━"

  send_tg "${msg}"
}

main() {
  umask 077; export LC_ALL=C
  load_config; require_cmds; build_and_send "$@"
}

main "$@"
REPORTER_EOF

  install -o root -g root -m 750 "${tmp_report}" "${REPORT_SCRIPT}"
  rm -f "${tmp_report}"
}

write_service_unit() {
  cat >"${SERVICE_FILE}" <<'SERVICE_EOF'
[Unit]
Description=Send vnStat traffic report to Telegram
After=network-online.target vnstat.service
Wants=network-online.target vnstat.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/traffic-telegram-report
User=root
Group=root
UMask=0077
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
SERVICE_EOF
}

write_timer_unit() {
  cat >"${TIMER_FILE}" <<'TIMER_EOF'
[Unit]
Description=Run Telegram traffic report daily at 20:00

[Timer]
OnCalendar=*-*-* 20:00:00
Persistent=true
AccuracySec=1min
Unit=traffic-telegram-report.service

[Install]
WantedBy=timers.target
TIMER_EOF
  systemctl daemon-reload
  systemctl enable --now "${APP_NAME}.timer"
}

send_test() {
  log '发送测试消息...'; "${REPORT_SCRIPT}" --test || \
    die '测试发送失败。请确认 Bot 已加入目标会话，且 Chat ID 正确。'
}

print_summary() {
  local ifname="$1"
  printf '\n安装完成。\n'
  printf '  监控网卡：  %s\n'   "${ifname}"
  printf '  汇报时间：  每天 20:00（服务器本地时区）\n'
  printf '  配置文件：  %s（仅 root 可读）\n'  "${CONFIG_FILE}"
  printf '  查看定时器：systemctl status %s.timer\n'   "${APP_NAME}"
  printf '  立即发送：  systemctl start %s.service\n'  "${APP_NAME}"
  printf '  查看日志：  journalctl -u %s.service\n'    "${APP_NAME}"
  printf '  卸载：      bash $0 --uninstall\n'
  if ${VNSTAT_WAS_INSTALLED}; then
    printf '\n注意：vnStat 是本次新安装，只能统计安装后的流量，无法补算历史。\n'
  else
    printf '\nvnStat 已存在，流量数据包含之前的统计记录。\n'
  fi
}

uninstall_app() {
  systemctl disable --now "${APP_NAME}.timer" >/dev/null 2>&1 || true
  rm -f "${REPORT_SCRIPT}" "${CONFIG_FILE}" "${SERVICE_FILE}" "${TIMER_FILE}"
  systemctl daemon-reload; systemctl reset-failed >/dev/null 2>&1 || true
  log '已卸载流量汇报服务；vnStat 软件及数据库未删除。'
}

main() {
  local ifname token chat_id
  require_root
  if [[ "${1:-}" == '--uninstall' ]]; then uninstall_app; return; fi
  check_debian13
  token="$(resolve_token)"; chat_id="$(resolve_chat_id)"
  install_deps
  ifname="$(detect_interface)"
  configure_vnstat "${ifname}"
  write_config "${ifname}" "${token}" "${chat_id}"
  write_reporter
  write_service_unit
  write_timer_unit
  send_test
  print_summary "${ifname}"
}

main "$@"
