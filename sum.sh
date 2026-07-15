#!/usr/bin/env bash
set -Eeuo pipefail

readonly APP_NAME="traffic-telegram-report"
readonly REPORT_SCRIPT="/usr/local/sbin/${APP_NAME}"
readonly CONFIG_FILE="/etc/${APP_NAME}.conf"
readonly SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
readonly TIMER_FILE="/etc/systemd/system/${APP_NAME}.timer"
readonly CF_SERVICE_FILE="/etc/systemd/system/${APP_NAME}-cf.service"
readonly CF_TIMER_FILE="/etc/systemd/system/${APP_NAME}-cf.timer"

VNSTAT_WAS_INSTALLED=false
TG_ENABLED=false

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
validate_mid() { [[ "$1" =~ ^[A-Za-z0-9._:-]{1,64}$ ]]; }
validate_cftoken() { [[ "$1" =~ ^[A-Za-z0-9._~+/-]{8,256}$ ]]; }

# ─── 参数解析（环境变量优先） ───
# TG 可选：ttoken + tid 都提供才启用 TG 日报
resolve_ttoken() {
  local val="${ttoken:-}"
  [[ -z "${val}" ]] && printf '' && return 0
  validate_token "${val}" || die 'Bot Token 格式无效。'
  printf '%s' "${val}"
}
resolve_tid() {
  local val="${tid:-}"
  [[ -z "${val}" ]] && printf '' && return 0
  validate_chat_id "${val}" || die 'Chat ID 应为纯数字，可带负号。'
  printf '%s' "${val}"
}
resolve_ttime() {
  local val="${ttime:-20:00:00}"
  validate_time "${val}" || die "ttime 格式无效，应为 HH:MM:SS，例如 20:00:00。"
  printf '%s' "${val}"
}

# CF 必选
resolve_mid() {
  local val="${mid:-}"
  if [[ -z "${val}" ]]; then
    read -r -p '请输入机器 ID（如 hk-1）: ' val
  fi
  validate_mid "${val}" || die "机器 ID 应为 1-64 位字母数字及 ._-: 组合。"
  printf '%s' "${val}"
}
resolve_cftoken() {
  local val="${cftoken:-}"
  if [[ -z "${val}" ]]; then
    read -r -s -p '请输入 CF 上报 Token: ' val; printf '\n'
  fi
  validate_cftoken "${val}" || die 'cftoken 格式无效。'
  printf '%s' "${val}"
}
resolve_cfurl() {
  local val="${cfurl:-}"
  if [[ -z "${val}" ]]; then
    read -r -p '请输入 CF Worker 上报地址（https://...）: ' val
  fi
  validate_url "${val}" || die 'cfurl 须为 https:// 开头的有效 URL。'
  printf '%s' "${val}"
}
resolve_cftime() {
  local val="${cftime:-0 * * * *}"
  validate_cron "${val}" || die "cftime 格式无效，应为 5 段 cron，例如：0 * * * *"
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
  local ifname="$1" mid="$2" cftoken="$3" cfurl="$4" tg_token="$5" tg_cid="$6"
  local tmp; tmp="$(mktemp)"; chmod 600 "${tmp}"
  {
    printf 'INTERFACE=%s\n' "${ifname}"
    printf 'MACHINE_ID=%s\n' "${mid}"
    printf 'CF_TOKEN=%s\n' "${cftoken}"
    printf 'CF_URL=%s\n' "${cfurl}"
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
    esac
  done <"${CONFIG}"
  [[ "${INTERFACE}" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || { log_error "INTERFACE 格式无效。"; return 1; }
  [[ "${MACHINE_ID}" =~ ^[A-Za-z0-9._:-]{1,64}$ ]] || { log_error "MACHINE_ID 格式无效。"; return 1; }
  [[ "${CF_TOKEN}" =~ ^[A-Za-z0-9._~+/-]{8,256}$ ]] || { log_error "CF_TOKEN 格式无效。"; return 1; }
  [[ -n "${CF_URL}" ]] || { log_error "CF_URL 为空。"; return 1; }
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

# ─── CF 上报（必选） ───
send_cf() {
  local payload="$(jq -nc \
    --arg mid "${MACHINE_ID}" \
    --arg host "$(hostname)" \
    --arg iface "${INTERFACE}" \
    --argjson ts "$(date +%s)" \
    --argjson tr_rx "${TR_RX}" \
    --argjson tr_tx "${TR_TX}" \
    --argjson mr_rx "${MR_RX}" \
    --argjson mr_tx "${MR_TX}" \
    --arg y "${STAT_YEAR}" \
    --argjson m "${STAT_MONTH}" \
    --argjson d "${STAT_DAY}" \
    '{
      machine_id: $mid, hostname: $host, interface: $iface, ts: $ts,
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
    "")          run_tg; run_cf ;;
    *)           log_error "未知参数：${1}"; return 1 ;;
  esac
}

main "$@"
REPORTER_EOF

  install -o root -g root -m 750 "${tmp_report}" "${REPORT_SCRIPT}"
  rm -f "${tmp_report}"
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
Persistent=true; AccuracySec=1min; Unit=${APP_NAME}-cf.service
[Install]
WantedBy=timers.target
TIMER_EOF
}

enable_timers() {
  local tg_enabled="$1"
  systemctl daemon-reload
  systemctl enable --now "${APP_NAME}-cf.timer"
  if [[ "${tg_enabled}" == "1" ]]; then
    systemctl enable --now "${APP_NAME}.timer"
  else
    systemctl disable --now "${APP_NAME}.timer" >/dev/null 2>&1 || true
    rm -f "${SERVICE_FILE}" "${TIMER_FILE}"
    systemctl daemon-reload
  fi
}

send_test() {
  log '发送 CF 测试上报...'
  "${REPORT_SCRIPT}" --cf || die 'CF 测试上报失败。请检查 cfurl / cftoken / mid。'
  if [[ "${TG_ENABLED}" == "true" ]]; then
    log '发送 Telegram 测试消息...'
    "${REPORT_SCRIPT}" --test || die 'Telegram 测试发送失败。'
  fi
}

print_summary() {
  local ifname="$1" tg_time="$2" cf_cron="$3" mid="$4"
  printf '\n安装完成。\n'
  printf '  机器 ID：    %s\n'   "${mid}"
  printf '  监控网卡：  %s\n'   "${ifname}"
  printf '  CF 上报：    cron %s\n' "${cf_cron}"
  if [[ "${TG_ENABLED}" == "true" ]]; then
    printf '  TG 汇报：    每天 %s\n' "${tg_time}"
  else
    printf '  TG 汇报：    未启用（设置 ttoken+tid 可开启）\n'
  fi
  printf '  配置文件：   %s（仅 root 可读）\n' "${CONFIG_FILE}"
  printf '  立即 CF 上报：systemctl start %s-cf.service\n' "${APP_NAME}"
  if [[ "${TG_ENABLED}" == "true" ]]; then
    printf '  立即 TG 发送：systemctl start %s.service\n' "${APP_NAME}"
  fi
  printf '  查看日志：   journalctl -u %s-cf.service\n' "${APP_NAME}"
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
  rm -f "${REPORT_SCRIPT}" "${CONFIG_FILE}" \
    "${SERVICE_FILE}" "${TIMER_FILE}" \
    "${CF_SERVICE_FILE}" "${CF_TIMER_FILE}"
  systemctl daemon-reload; systemctl reset-failed >/dev/null 2>&1 || true
  log '已卸载流量汇报服务；vnStat 软件及数据库未删除。'
}

main() {
  local ifname mid cftoken cfurl tg_token tg_cid tg_time cf_cron
  require_root
  if [[ "${1:-}" == '--uninstall' ]]; then uninstall_app; return; fi
  check_debian13

  # 解析参数
  tg_token="$(resolve_ttoken)"
  tg_cid="$(resolve_tid)"
  tg_time="$(resolve_ttime)"
  if [[ -n "${tg_token}" && -n "${tg_cid}" ]]; then
    TG_ENABLED=true
  fi
  mid="$(resolve_mid)"
  cftoken="$(resolve_cftoken)"
  cfurl="$(resolve_cfurl)"
  cf_cron="$(resolve_cftime)"

  install_deps
  ifname="$(detect_interface)"
  configure_vnstat "${ifname}"
  write_config "${ifname}" "${mid}" "${cftoken}" "${cfurl}" "${tg_token}" "${tg_cid}"
  write_reporter

  # CF 服务/定时（始终安装）
  write_cf_service_unit
  write_cf_timer "${cf_cron}"

  # TG 服务/定时（可选）
  if [[ "${TG_ENABLED}" == "true" ]]; then
    write_service_unit "--tg"
    write_tg_timer "${tg_time}"
  fi

  enable_timers "$( [[ "${TG_ENABLED}" == "true" ]] && printf 1 || printf 0 )"
  send_test
  print_summary "${ifname}" "${tg_time}" "${cf_cron}" "${mid}"
}

main "$@"
