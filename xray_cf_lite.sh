#!/usr/bin/env bash
set -euo pipefail

# ── 常量 ────────────────────────────────────────────────
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_CONFIG_PATH="$XRAY_CONFIG_DIR/config.json"
XRAY_BINARY="/usr/local/bin/xray"
STATE_DIR="${XRAY_CF_LITE_STATE_DIR:-/etc/xray-cf-lite}"
STATE_PATH="$STATE_DIR/state.json"
CF_ACCOUNT_PATH="$STATE_DIR/cf_account.json"
LOCAL_SUB_DIR="$STATE_DIR/local_sub"
LOCAL_SCRIPT_PATH="$STATE_DIR/xray_cf_lite.sh"
LAST_LINKS_PATH="${XRAY_CF_LITE_LAST_LINKS_PATH:-$(pwd)/cf_lite_last_links.txt}"
SHORTCUT_PATH="${XRAY_CF_LITE_SHORTCUT_PATH:-/usr/local/bin/x}"
SCRIPT_RAW_URL="${XRAY_CF_LITE_RAW_URL:-https://raw.githubusercontent.com/TonyDG233/xray-cf-lite/main/xray_cf_lite.sh}"
LOCAL_SUB_PY="$STATE_DIR/local_sub_server.py"
LOCAL_SUB_SERVICE="${LOCAL_SUB_SERVICE:-cflite-sub}"
SYSTEMD_DIR="${XRAY_CF_LITE_SYSTEMD_DIR:-/etc/systemd/system}"
INITD_DIR="${XRAY_CF_LITE_INITD_DIR:-/etc/init.d}"
SKIP_SERVICE="${XRAY_CF_LITE_SKIP_SERVICE:-0}"

CF_API="https://api.cloudflare.com/client/v4"
MANAGED_PREFIX="xray-cf-lite "
XRAY_INSTALL_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
DEFAULT_SUB_BASE="https://yx-auto.pages.dev"

DEFAULT_IP_URLS=(
    "https://raw.githubusercontent.com/gshtwy/CF-DNS-Clone/refs/heads/main/wetest-cloudflare-v4.txt"
    "https://edt-aio-nav.pages.dev/cm/ct_50.txt"
    "https://edt-aio-nav.pages.dev/wetest/ipv4.txt"
    "https://edt-aio-nav.pages.dev/domain/all.txt"
)

declare -A PROTO_SUFFIX=([vless]="vl" [trojan]="tr" [vmess]="vm")
declare -A PROTO_LABEL=([vless]="VLESS" [trojan]="TROJAN" [vmess]="VMESS")

# ── 工具 ──────────────────────────────────────────────
die()     { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
# 状态提示一律走 stderr：有些函数用 stdout 返回 JSON（如 cf_relax_security），
# 提示混进去会让调用方的 $(...) 拿到「提示+JSON」，jq --argjson 直接解析失败。
ok()      { printf '\033[32m✓\033[0m %s\n' "$*" >&2; }
info()    { printf '\033[36m·\033[0m %s\n' "$*" >&2; }
need_cmd(){ command -v "$1" &>/dev/null || die "缺少依赖: $1"; }


urlencode() {
    local s="$1" c
    local -i i
    for ((i=0; i<${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) printf '%s' "$c" ;;
            *) printf '%%%02X' "'$c" ;;
        esac
    done
}

# ── 私网/保留地址判定（供 is_safe_url 使用） ──────────
# 返回 0 表示该主机处于私网/环回/链路本地/保留段或内部域名，应拒绝；
# 返回 1 表示可放行。域名相关规则与 Worker 侧 cf_sub_worker.js 保持同口径。

# 将 IPv6 字面量展开为 32 位小写十六进制串（无冒号）；语法非法时返回 1。
_ipv6_expand() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9a-f:.]+$ ]] || return 1

    # 末尾内嵌点分 IPv4（如 ::ffff:127.0.0.1）先转换为两个十六进制组
    local last="${ip##*:}" a b c d
    if [[ "$last" == *.* ]]; then
        [[ "$last" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
        a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"; c="${BASH_REMATCH[3]}"; d="${BASH_REMATCH[4]}"
        (( 10#$a <= 255 && 10#$b <= 255 && 10#$c <= 255 && 10#$d <= 255 )) || return 1
        ip="${ip%:*}:$(printf '%02x%02x' "$((10#$a))" "$((10#$b))"):$(printf '%02x%02x' "$((10#$c))" "$((10#$d))")"
    fi

    local left="" right="" i g hex=""
    local -a larr=() rarr=()
    if [[ "$ip" == *::* ]]; then
        left="${ip%%::*}"
        right="${ip#*::}"
        [[ "$right" == *::* ]] && return 1
    else
        left="$ip"
    fi
    [[ -n "$left" ]] && IFS=':' read -r -a larr <<< "$left"
    [[ -n "$right" ]] && IFS=':' read -r -a rarr <<< "$right"

    if [[ "$ip" == *::* ]]; then
        (( ${#larr[@]} + ${#rarr[@]} < 8 )) || return 1
        for ((i = ${#larr[@]} + ${#rarr[@]}; i < 8; i++)); do larr+=("0"); done
        if (( ${#rarr[@]} > 0 )); then larr+=("${rarr[@]}"); fi
    else
        (( ${#larr[@]} == 8 )) || return 1
    fi

    for g in "${larr[@]}"; do
        [[ "$g" =~ ^[0-9a-f]{1,4}$ ]] || return 1
        hex+=$(printf '%04x' "$((16#$g))")
    done
    printf '%s' "$hex"
}

# IPv4 私网/环回/链路本地/保留段判定。
_ipv4_is_private_or_reserved() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local o1=$((10#${BASH_REMATCH[1]})) o2=$((10#${BASH_REMATCH[2]})) o3=$((10#${BASH_REMATCH[3]}))
    if (( o1 == 0 || o1 == 10 || o1 == 127 )); then return 0; fi              # 0/8 10/8 127/8
    if (( o1 == 100 && o2 >= 64 && o2 <= 127 )); then return 0; fi            # 100.64/10
    if (( o1 == 169 && o2 == 254 )); then return 0; fi                        # 169.254/16
    if (( o1 == 172 && o2 >= 16 && o2 <= 31 )); then return 0; fi             # 172.16/12
    if (( o1 == 192 && o2 == 0 && o3 == 0 )); then return 0; fi               # 192.0.0/24
    if (( o1 == 192 && o2 == 0 && o3 == 2 )); then return 0; fi               # 192.0.2/24
    if (( o1 == 192 && o2 == 168 )); then return 0; fi                        # 192.168/16
    if (( o1 == 198 && (o2 == 18 || o2 == 19) )); then return 0; fi           # 198.18/15
    if (( o1 == 198 && o2 == 51 && o3 == 100 )); then return 0; fi            # 198.51.100/24
    if (( o1 == 203 && o2 == 0 && o3 == 113 )); then return 0; fi             # 203.0.113/24
    if (( o1 >= 224 )); then return 0; fi                                     # 224/4 组播 + 240/4 保留
    return 1
}

# IPv6 私网/环回/链路本地/保留段判定（基于展开后的十六进制前缀）。
_ipv6_is_private_or_reserved() {
    local ip="$1" hex
    hex=$(_ipv6_expand "$ip") || return 1

    # ::/96：覆盖 ::、::1 与已废弃的 IPv4-compatible 形式
    if [[ "${hex:0:24}" == "000000000000000000000000" ]]; then return 0; fi
    # ::ffff:0:0/96（IPv4-mapped）：展开尾部 IPv4 后按 IPv4 规则判断
    if [[ "${hex:0:24}" == "00000000000000000000ffff" ]]; then
        local t="${hex:24:8}"
        _ipv4_is_private_or_reserved "$((16#${t:0:2})).$((16#${t:2:2})).$((16#${t:4:2})).$((16#${t:6:2}))"
        return
    fi
    if [[ "${hex:0:24}" == "0064ff9b0000000000000000" ]]; then return 0; fi   # 64:ff9b::/96 NAT64
    if [[ "${hex:0:2}" == "fc" || "${hex:0:2}" == "fd" ]]; then return 0; fi  # fc00::/7 ULA
    case "${hex:0:3}" in fe8|fe9|fea|feb) return 0 ;; esac                    # fe80::/10 链路本地
    if [[ "${hex:0:2}" == "ff" ]]; then return 0; fi                          # ff00::/8 组播
    if [[ "${hex:0:4}" == "2002" ]]; then return 0; fi                        # 2002::/16 6to4
    if [[ "${hex:0:8}" == "20010000" ]]; then return 0; fi                    # 2001:0::/32 Teredo
    return 1
}

# 内部/回环别名域名判定（与 Worker 侧 BLOCKED_DOMAIN_SUFFIXES 同口径）。
_domain_is_blocked() {
    local h="$1" s
    for s in localhost localtest.me lvh.me nip.io sslip.io xip.io traefik.me vcap.me lacolhost.com; do
        if [[ "$h" == "$s" || "$h" == *".$s" ]]; then
            return 0
        fi
    done
    return 1
}

# 按主机形态分发私网/保留判定；返回 0 表示应拒绝。
is_private_or_reserved_host() {
    local host="$1"
    if [[ "$host" == *:* ]]; then
        _ipv6_is_private_or_reserved "$host"
        return
    fi
    if [[ "$host" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        _ipv4_is_private_or_reserved "$host"
        return
    fi
    _domain_is_blocked "$host"
}

# 统一 URL 安全校验：仅允许 http/https，拒绝 shell 元字符、空白、控制字符，
# 长度上限 2048；主机按严格白名单解析（authority -> 拒绝 userinfo -> 方括号
# IPv6 -> 最后冒号拆 host/port -> 三形态白名单），任何非标准写法一律拒绝，
# 且不得指向私网/环回/链路本地/保留地址或内部域名。
is_safe_url() {
    local url="$1"
    (( ${#url} > 0 && ${#url} <= 2048 )) || return 1
    [[ "$url" =~ ^https?:// ]] || return 1

    # 任何可能被 shell 二次解释的字符一律拒绝
    case "$url" in
        *'$'*|*'`'*|*'"'*|*"'"*|*'('*|*')'*|*';'*|*'|'*|*'&'*|*'<'*|*'>'*|*'\'*|*' '*|*$'\t'*|*$'\n'*|*$'\r'*) return 1 ;;
    esac

    # 取 authority：scheme:// 之后、第一个 / ? # 之前
    local rest="${url#*://}"
    local authority="${rest%%[/?#]*}"

    # 拒绝 userinfo：curl 会把 @ 之后当作真实主机，形成主机混淆绕过
    [[ "$authority" == *'@'* ]] && return 1

    local host="" port=""
    if [[ "$authority" == *'['* || "$authority" == *']'* ]]; then
        # 方括号 IPv6：必须以 [ 开头、以 ] 闭合，其后只允许 [:port]
        [[ "$authority" == \[* ]] || return 1
        [[ "$authority" == *']'* ]] || return 1
        host="${authority%%]*}"
        host="${host#[}"
        local after="${authority#*]}"
        if [[ -n "$after" ]]; then
            [[ "$after" =~ ^:[0-9]{1,5}$ ]] || return 1
            port="${after#:}"
        fi
    else
        # host 本身不含 :，按最后一个 : 拆 host/port；冒号后为空视为非法
        if [[ "$authority" == *':'* ]]; then
            host="${authority%:*}"
            port="${authority##*:}"
            [[ -n "$port" ]] || return 1
        else
            host="$authority"
        fi
    fi

    [[ -n "$host" ]] || return 1
    host="${host,,}"

    # 显式拒绝尾随点（不做静默剥离）
    [[ "$host" == *'.' ]] && return 1

    # 端口：若存在必须是 1..65535
    if [[ -n "$port" ]]; then
        [[ "$port" =~ ^[0-9]{1,5}$ ]] || return 1
        (( 10#$port >= 1 && 10#$port <= 65535 )) || return 1
    fi

    # 形态 1：严格十进制点分四段 IPv4（每段无前导零，恰好 4 段）
    if [[ "$host" =~ ^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])$ ]]; then
        is_private_or_reserved_host "$host" && return 1
        return 0
    fi

    # 形态 2：方括号 IPv6（展开后必须恰好 32 位十六进制），再走私网判定
    if [[ "$authority" == \[* ]]; then
        [[ "$host" == *':'* ]] || return 1
        local hex
        hex=$(_ipv6_expand "$host") || return 1
        [[ "$hex" =~ ^[0-9a-f]{32}$ ]] || return 1
        is_private_or_reserved_host "$host" && return 1
        return 0
    fi

    # 形态 3：域名——必须含点、至少一个字母、TLD 全字母、以字母或数字结尾
    [[ "$host" == *'.'* ]] || return 1
    [[ "$host" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || return 1
    [[ "$host" =~ [a-z] ]] || return 1
    [[ "${host##*.}" =~ ^[a-z]+$ ]] || return 1
    is_private_or_reserved_host "$host" && return 1
    return 0
}

gen_uuid() { cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen | tr '[:upper:]' '[:lower:]'; }

# ── init 系统检测 ─────────────────────────────────────
INIT_SYSTEM=""
detect_init() {
    if command -v systemctl &>/dev/null && systemctl --version &>/dev/null 2>&1; then
        INIT_SYSTEM="systemd"
    elif command -v rc-service &>/dev/null; then
        INIT_SYSTEM="openrc"
    else
        die "不支持的 init 系统（需要 systemd 或 OpenRC）"
    fi
}

# ── 包管理器 ──────────────────────────────────────────
install_deps() {
    local missing=()
    command -v curl  &>/dev/null || missing+=(curl)
    command -v jq    &>/dev/null || missing+=(jq)
    command -v unzip &>/dev/null || missing+=(unzip)
    [[ ${#missing[@]} -eq 0 ]] && return

    echo "安装依赖: ${missing[*]}"
    if command -v apk &>/dev/null; then
        apk add --no-cache "${missing[@]}"
    elif command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq "${missing[@]}"
    elif command -v yum &>/dev/null; then
        yum install -y "${missing[@]}"
    else
        die "无法安装依赖 ${missing[*]}，请手动安装"
    fi
}

# ── xray 服务管理 ────────────────────────────────────
XRAY_OPENRC_SCRIPT="/etc/init.d/xray"

write_openrc_script() {
    cat > "$XRAY_OPENRC_SCRIPT" << 'INITEOF'
#!/sbin/openrc-run
name="xray"
description="Xray proxy server"
command="/usr/local/bin/xray"
command_args="run -config /usr/local/etc/xray/config.json"
command_background=true
pidfile="/run/xray.pid"
output_log="/var/log/xray.log"
error_log="/var/log/xray.log"
respawn_delay=1
respawn_max=0
respawn_period=86400
supervise_daemon_args="--respawn-delay ${respawn_delay} --respawn-max ${respawn_max} --respawn-period ${respawn_period}"
supervisor=supervise-daemon
depend() { need net; after firewall; }
INITEOF
    chmod +x "$XRAY_OPENRC_SCRIPT"
}

svc_enable()    { if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl enable xray &>/dev/null; else rc-update add xray default &>/dev/null; fi; true; }
svc_start()     { if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl restart xray; else [[ -f "$XRAY_OPENRC_SCRIPT" ]] || write_openrc_script; rc-service xray restart; fi; }
svc_stop()      { if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl stop xray &>/dev/null; systemctl disable xray &>/dev/null; else rc-service xray stop &>/dev/null; rc-update del xray default &>/dev/null; fi; true; }
svc_is_active() { if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl is-active xray &>/dev/null; else rc-service xray status &>/dev/null 2>&1; fi; }

ensure_systemd_restart() {
    # 确保 systemd 下 xray 崩溃自动重启
    local drop="/etc/systemd/system/xray.service.d"
    if [[ "$INIT_SYSTEM" == "systemd" && ! -f "$drop/restart.conf" ]]; then
        mkdir -p "$drop"
        cat > "$drop/restart.conf" << 'SDEOF'
[Service]
Restart=on-failure
RestartSec=1
SDEOF
        systemctl daemon-reload
    fi
}

restart_xray() {
    [[ "$INIT_SYSTEM" == "systemd" ]] && ensure_systemd_restart
    svc_enable
    svc_start || die "xray 重启失败"
    sleep 1
    svc_is_active || die "xray 未正常启动，请查看日志"
    ok "xray 服务已启动"
}

stop_xray() { svc_stop; }

# ── 网络检测 ─────────────────────────────────────────
get_public_ip() {
    local ip
    for url in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip; do
        ip=$(curl -sf --max-time 8 "$url" 2>/dev/null) && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "$ip" && return
    done
    die "获取公网 IPv4 失败"
}

# detect_nat 猜测本机是直连公网还是在 NAT 后面。
#
# 只看「公网 IP 有没有绑在网卡上」会误判：云厂商（AWS/GCP/阿里云等）常用一对一 NAT，
# 网卡上是内网地址，但公网端口其实直达。这类机器判成 NAT 会逼用户去填并不存在的端口映射。
# 所以这里只作为默认建议，最终由用户确认（见 prompt_net_mode）。
detect_nat() {
    local public_ip
    public_ip=$(get_public_ip)
    if ip addr show 2>/dev/null | grep -qE "inet ${public_ip}/"; then
        echo "direct"
        return
    fi
    echo "nat"
}

# prompt_net_mode 拿探测结果当默认值，让用户可以改。
#
# 探测不可能百分百准，判错了又没法改的话，装出来的配置就是错的（issue #1）。
net_mode_label() {
    [[ "$1" == "direct" ]] && echo "直连（公网端口直达本机）" || echo "NAT（需要端口映射）"
}

prompt_net_mode() {
    local detected="$1" ans
    echo >&2
    info "网络环境探测结果: $(net_mode_label "$detected")" >&2
    if [[ "$detected" == "nat" ]]; then
        echo "  如果这台机器有独立公网 IP、外部能直接连到你要开的端口（常见于云厂商的一对一 NAT）," >&2
        echo "  这里就该选直连，否则会让你填一堆并不存在的端口映射。" >&2
    else
        echo "  如果这台机器其实在 NAT/软路由后面，对外端口和本机监听端口不一致，这里要选 NAT。" >&2
    fi
    read -rp "使用哪种模式? (1=直连, 2=NAT, 回车=用探测结果): " ans
    case "$ans" in
        1) echo "direct" ;;
        2) echo "nat" ;;
        "") echo "$detected" ;;
        *) die "无效选项: $ans" ;;
    esac
}

get_listening_ports() {
    ss -tlnH 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un | tr '\n' ' '
}

rand_port() {
    local existing="$1" p
    while true; do
        p=$(( RANDOM % 50000 + 10000 ))
        echo "$existing" | grep -qw "$p" || { echo "$p"; return; }
    done
}

# ── CF API ────────────────────────────────────────────
cf_call() {
    local method="$1" endpoint="$2" data="${3:-}"
    local args=(-s -f -X "$method" -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" -H "Content-Type: application/json")
    [[ -n "$data" ]] && args+=(-d "$data")
    curl "${args[@]}" "${CF_API}${endpoint}"
}

cf_call_raw() {
    local method="$1" endpoint="$2" data="${3:-}"
    local args=(-s -X "$method" -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" -H "Content-Type: application/json")
    [[ -n "$data" ]] && args+=(-d "$data")
    curl "${args[@]}" "${CF_API}${endpoint}"
}

# ── CF 凭据 ───────────────────────────────────────────
CF_EMAIL="" CF_KEY=""

load_cf_account() {
    [[ -f "$CF_ACCOUNT_PATH" ]] || return 1
    CF_EMAIL=$(jq -r '.email // ""' "$CF_ACCOUNT_PATH")
    CF_KEY=$(jq -r '.api_key // ""' "$CF_ACCOUNT_PATH")
    [[ -n "$CF_EMAIL" && -n "$CF_KEY" ]]
}

save_cf_account() {
    mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"
    jq -n --arg e "$CF_EMAIL" --arg k "$CF_KEY" '{email:$e,api_key:$k}' > "$CF_ACCOUNT_PATH"
    chmod 600 "$CF_ACCOUNT_PATH"
}

# 验证 CF 凭据是否有效（用 verify 接口，避免拿到无效 key 继续跑）
cf_verify_credentials() {
    local r
    r=$(curl -s -X GET "${CF_API}/user/tokens/verify" \
        -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" -H "Content-Type: application/json")
    # Global API Key 在 tokens/verify 上可能不适用，回退到列 zones 验证
    if echo "$r" | jq -e '.success == true' &>/dev/null; then
        return 0
    fi
    r=$(curl -s -X GET "${CF_API}/zones?per_page=1" \
        -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" -H "Content-Type: application/json")
    echo "$r" | jq -e '.success == true' &>/dev/null
}

prompt_cf() {
    # 先尝试复用已保存凭据
    if load_cf_account; then
        local masked="${CF_KEY:0:6}...${CF_KEY: -4}"
        read -rp "复用已保存 CF 凭据 ($CF_EMAIL, Key=$masked)? (Y/n): " ans
        if [[ "${ans,,}" =~ ^(|y|yes)$ ]]; then
            if cf_verify_credentials; then
                return 0
            fi
            echo "已保存的 CF 凭据校验失败，请重新输入"
        fi
    fi
    # 循环让用户输入直到校验通过
    while true; do
        read -rp "Cloudflare 邮箱: " CF_EMAIL || die "输入已中断"
        read -rsp "Cloudflare Global API Key: " CF_KEY || die "输入已中断"; echo
        if [[ -z "$CF_EMAIL" || -z "$CF_KEY" ]]; then
            echo "邮箱和 API Key 不能为空，请重试"
            continue
        fi
        echo -n "校验凭据... "
        if cf_verify_credentials; then
            echo "通过"
            save_cf_account
            return 0
        fi
        echo "失败：邮箱或 API Key 错误，请重新输入（Ctrl+C 退出）"
    done
}

# ── CF DNS / SSL / Origin Rules ───────────────────────
cf_find_zone() {
    local domain="$1" zones best_name="" best_id=""
    zones=$(cf_call GET "/zones?per_page=100" | jq -r '.result[] | "\(.name) \(.id)"')
    while IFS=' ' read -r zone_name zone_id; do
        if [[ "$domain" == "$zone_name" || "$domain" == *".$zone_name" ]]; then
            [[ ${#zone_name} -gt ${#best_name} ]] && best_name="$zone_name" && best_id="$zone_id"
        fi
    done <<< "$zones"
    [[ -n "$best_id" ]] || return 1
    echo "$best_id"
}

cf_get_dns() {
    cf_call GET "/zones/$1/dns_records?type=A&name=$2" | jq '.result[0] // empty'
}

cf_upsert_dns() {
    local zone_id="$1" domain="$2" ip="$3"
    local payload existing
    payload=$(jq -n --arg n "$domain" --arg c "$ip" '{type:"A",name:$n,content:$c,proxied:true,ttl:1}')
    existing=$(cf_get_dns "$zone_id" "$domain")
    if [[ -n "$existing" ]]; then
        local rid; rid=$(echo "$existing" | jq -r '.id')
        cf_call PUT "/zones/${zone_id}/dns_records/${rid}" "$payload" | jq -r '.result.id'
    else
        cf_call POST "/zones/${zone_id}/dns_records" "$payload" | jq -r '.result.id'
    fi
}

cf_get_ssl()  { cf_call GET "/zones/$1/settings/ssl" | jq -r '.result.value'; }
cf_set_ssl()  { cf_call PATCH "/zones/$1/settings/ssl" "$(jq -n --arg v "$2" '{value:$v}')" >/dev/null; }

# ── CF 安全规则 ───────────────────────────────────────
cf_get_security_level() { cf_call GET "/zones/$1/settings/security_level" | jq -r '.result.value'; }
cf_set_security_level() { cf_call PATCH "/zones/$1/settings/security_level" "$(jq -n --arg v "$2" '{value:$v}')" >/dev/null; }

cf_get_browser_check() { cf_call GET "/zones/$1/settings/browser_check" | jq -r '.result.value'; }
cf_set_browser_check() { cf_call PATCH "/zones/$1/settings/browser_check" "$(jq -n --arg v "$2" '{value:$v}')" >/dev/null; }

cf_get_bot_management() { cf_call_raw GET "/zones/$1/bot_management" | jq '.result // {}'; }

cf_set_bot_fight_off() {
    local zone_id="$1"
    cf_call_raw PUT "/zones/${zone_id}/bot_management" "$(jq -n '{
        enable_js: false,
        sbfm_likely_automated: "allow",
        sbfm_definitely_automated: "allow",
        sbfm_verified_bots: "allow",
        sbfm_static_resource_protection: false
    }')" | jq -e '.success' &>/dev/null
}

cf_restore_bot_management() {
    local zone_id="$1" backup="$2"
    # 只恢复我们改过的字段
    local payload
    payload=$(echo "$backup" | jq '{
        enable_js: .enable_js,
        sbfm_likely_automated: .sbfm_likely_automated,
        sbfm_definitely_automated: .sbfm_definitely_automated,
        sbfm_verified_bots: .sbfm_verified_bots,
        sbfm_static_resource_protection: .sbfm_static_resource_protection
    }')
    cf_call_raw PUT "/zones/${zone_id}/bot_management" "$payload" | jq -e '.success' &>/dev/null
}

# 安装时：备份安全设置 -> 关闭拦截
cf_relax_security() {
    local zone_id="$1"
    local sec_level bot_mgmt browser_check

    sec_level=$(cf_get_security_level "$zone_id")
    browser_check=$(cf_get_browser_check "$zone_id")
    bot_mgmt=$(cf_get_bot_management "$zone_id")

    # 降低 security level
    if [[ "$sec_level" != "essentially_off" ]]; then
        cf_set_security_level "$zone_id" "essentially_off"
        ok "Security Level: essentially_off"
    fi

    # 关闭 Browser Integrity Check
    if [[ "$browser_check" != "off" ]]; then
        cf_set_browser_check "$zone_id" "off"
        ok "Browser Check: off"
    fi

    # 关闭 Bot Fight Mode
    local sbfm_likely
    sbfm_likely=$(echo "$bot_mgmt" | jq -r '.sbfm_likely_automated // ""')
    if [[ "$sbfm_likely" != "allow" ]]; then
        cf_set_bot_fight_off "$zone_id"
        ok "Bot Fight Mode: 已关闭"
    fi

    # 返回备份 JSON
    jq -n --arg sl "$sec_level" --arg bc "$browser_check" --argjson bm "$bot_mgmt"         '{security_level:$sl, browser_check:$bc, bot_management:$bm}'
}

# 卸载时：恢复安全设置
cf_restore_security() {
    local zone_id="$1" backup="$2"
    [[ -z "$backup" || "$backup" == "null" ]] && return

    local sl bc bm
    sl=$(echo "$backup" | jq -r '.security_level // ""')
    bc=$(echo "$backup" | jq -r '.browser_check // ""')
    bm=$(echo "$backup" | jq '.bot_management // null')

    [[ -n "$sl" ]] && cf_set_security_level "$zone_id" "$sl" && ok "Security Level 已恢复: $sl"
    [[ -n "$bc" ]] && cf_set_browser_check "$zone_id" "$bc" && ok "Browser Check 已恢复: $bc"
    [[ "$bm" != "null" ]] && cf_restore_bot_management "$zone_id" "$bm" && ok "Bot Fight Mode 已恢复"
}

cf_get_origin_rules() {
    local r; r=$(cf_call_raw GET "/zones/$1/rulesets/phases/http_request_origin/entrypoint")
    echo "$r" | jq -r 'if .success then .result.rules // [] else [] end' 2>/dev/null || echo '[]'
}

cf_put_origin_rules() {
    local r; r=$(cf_call_raw PUT "/zones/$1/rulesets/phases/http_request_origin/entrypoint" \
        "$(jq -n --argjson r "$2" '{rules:$r}')")
    echo "$r" | jq -e '.success' &>/dev/null || die "Origin Rules 写入失败: $(echo "$r" | jq -c '.errors')"
}

# cf_port = 外部端口（CF Origin Rules 转发的目标端口）
build_new_origin_rules() {
    local domain="$1" routes_json="$2"
    echo "$routes_json" | jq --arg d "$domain" --arg pfx "$MANAGED_PREFIX" '[
        .[] | {
            description: ($pfx + .protocol + " " + .path),
            enabled: true,
            expression: ("(http.host eq \"" + $d + "\" and http.request.uri.path eq \"" + .path + "\")"),
            action: "route",
            action_parameters: { origin: { port: .cf_port } }
        }
    ]'
}

apply_origin_rules() {
    local zone_id="$1" domain="$2" routes_json="$3"
    local existing kept new_managed merged
    existing=$(cf_get_origin_rules "$zone_id")
    kept=$(echo "$existing" | jq --arg d "$domain" --arg pfx "$MANAGED_PREFIX" '[
        .[] | select(
            (.description | startswith($pfx) | not) or
            (.expression | ascii_downcase | contains("http.host eq \"" + ($d|ascii_downcase) + "\"") | not)
        )
    ]')
    new_managed=$(build_new_origin_rules "$domain" "$routes_json")
    merged=$(jq -n --argjson a "$kept" --argjson b "$new_managed" '$a + $b')
    cf_put_origin_rules "$zone_id" "$merged"
}

# ── xray 安装 ─────────────────────────────────────────
install_xray() {
    echo "正在安装 xray-core ..."

    # 优先尝试官方安装脚本（需要 systemd）
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        if bash -c "curl -fsSL $XRAY_INSTALL_URL | bash -s -- install" 2>/dev/null; then
            [[ -f "$XRAY_BINARY" ]] && { ok "xray-core 安装完成"; return; }
        fi
    fi

    # 回退：手动下载二进制
    info "使用手动安装方式"
    local arch
    case "$(uname -m)" in
        x86_64|amd64) arch="64" ;;
        aarch64|arm64) arch="arm64-v8a" ;;
        armv7*)        arch="arm32-v7a" ;;
        *)             die "不支持的架构: $(uname -m)" ;;
    esac

    # 直接用 releases/latest/download 直链，不走 GitHub API（未认证 API 每 IP 每小时仅 60 次，
    # NAT 小鸡共享出口极易撞限流导致取版本号失败）。版本号仅用于日志显示，取不到不致命。
    # 末尾 || true：脚本头部 set -euo pipefail，API 不可达时 curl 非 0 会经 pipefail
    # 冒泡成命令替换失败并触发 set -e 提前退出，永远走不到下面的直链下载。
    local ver=""
    ver=$(curl -sf "https://api.github.com/repos/XTLS/Xray-core/releases/latest" 2>/dev/null | jq -r '.tag_name' 2>/dev/null) || true
    [[ -n "$ver" && "$ver" != "null" ]] && info "xray $ver ($arch)" || info "xray latest ($arch)"

    local tmp="/tmp/xray-install-$$"
    mkdir -p "$tmp"
    curl -fsSL -o "$tmp/xray.zip" "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${arch}.zip" || die "下载失败"

    command -v unzip &>/dev/null || {
        command -v apk &>/dev/null && apk add --no-cache unzip
        command -v apt-get &>/dev/null && apt-get install -y -qq unzip
    }

    unzip -o "$tmp/xray.zip" xray -d /usr/local/bin/ || die "解压失败"
    chmod +x "$XRAY_BINARY"
    rm -rf "$tmp"

    # 下载 geodata
    local geo_dir="/usr/local/share/xray"
    mkdir -p "$geo_dir"
    for f in geoip.dat geosite.dat; do
        [[ -f "$geo_dir/$f" ]] || curl -fsSL -o "$geo_dir/$f" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/$f" 2>/dev/null || true
    done

    [[ -f "$XRAY_BINARY" ]] || die "安装后未找到 xray"
    ok "xray-core 安装完成: $($XRAY_BINARY version | head -1)"
}

# ── xray 配置生成 ─────────────────────────────────────
# 外部工具（fanout 等）注入的出站/路由统一带这个前缀，重建配置时予以保留。
EXTERNAL_TAG_PREFIX="fanout-"

# external_outbounds 从现有配置里捞出外部注入的出站。没有配置或没有匹配项时返回 []。
external_outbounds() {
    [[ -f "$XRAY_CONFIG_PATH" ]] || { echo '[]'; return; }
    jq --arg p "$EXTERNAL_TAG_PREFIX" \
        '[.outbounds // [] | .[] | select((.tag // "") | startswith($p))]' \
        "$XRAY_CONFIG_PATH" 2>/dev/null || echo '[]'
}

# external_routing_rules 捞出外部注入的分流规则，并把 inboundTag 重映射到新的入站 tag。
#
# 入站 tag 形如 in-<protocol>-<port>，改端口后 tag 会变，直接照搬旧规则会指向
# 已不存在的 inboundTag（xray 不报错，规则静默失效）。这里按协议重新匹配：
# 旧规则绑的是哪个协议，新配置里该协议的 tag 是什么，就替换成什么。
external_routing_rules() {
    local routes_json="$1"
    [[ -f "$XRAY_CONFIG_PATH" ]] || { echo '[]'; return; }

    # 协议 -> 新 tag 的映射
    local proto_map
    proto_map=$(echo "$routes_json" | jq '[.[] | {key:.protocol, value:("in-" + .protocol + "-" + (.listen_port|tostring))}] | from_entries')

    # 旧 tag -> 协议（从旧配置的 inbounds 里读，tag 可能已过时但协议是准的）
    local old_map
    old_map=$(jq '[.inbounds // [] | .[] | {key:(.tag // ""), value:(.protocol // "")}] | from_entries' \
        "$XRAY_CONFIG_PATH" 2>/dev/null) || { echo '[]'; return; }

    jq --arg p "$EXTERNAL_TAG_PREFIX" --argjson pm "$proto_map" --argjson om "$old_map" '
        [ .routing.rules // [] | .[]
          | select((.outboundTag // "") | startswith($p))
          | . as $rule
          | ( [ (.inboundTag // [])[] | $om[.] // empty | $pm[.] // empty ] | unique ) as $newtags
          | select($newtags | length > 0)
          | $rule + {inboundTag: $newtags}
        ]' "$XRAY_CONFIG_PATH" 2>/dev/null || echo '[]'
}

gen_xray_config() {
    local routes_json="$1" uid="$2"
    local inbounds
    inbounds=$(echo "$routes_json" | jq --arg uid "$uid" '[
        .[] | {
            tag: ("in-" + .protocol + "-" + (.listen_port|tostring)),
            listen: "0.0.0.0",
            port: .listen_port,
            protocol: .protocol,
            settings: (
                if .protocol == "vless" then {clients:[{id:$uid,flow:""}],decryption:"none"}
                elif .protocol == "trojan" then {clients:[{password:$uid}]}
                else {clients:[{id:$uid,alterId:0}]}
                end
            ),
            streamSettings: { network:"ws", security:"none", wsSettings:{path:.path} },
            sniffing: { enabled:true, destOverride:["http","tls"] }
        }
    ]')
    # 保留外部工具（如 fanout）注入的出站与分流规则。
    # 它们统一带 EXTERNAL_TAG_PREFIX 前缀，重新生成配置时原样带过来，
    # 否则用户在这里改个 UUID 就会把已配好的出口绑定悄悄冲掉，流量默默回到直连。
    local ext_outbounds ext_rules
    ext_outbounds=$(external_outbounds)
    ext_rules=$(external_routing_rules "$routes_json")

    jq -n --argjson inb "$inbounds" --argjson eob "$ext_outbounds" --argjson erl "$ext_rules" '{
        log:{loglevel:"warning"},
        inbounds:$inb,
        outbounds:([{tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}] + $eob),
        routing:{domainStrategy:"AsIs",rules:([{type:"field",outboundTag:"block",protocol:["bittorrent"]}] + $erl)}
    }'
}

write_xray_config() {
    mkdir -p "$XRAY_CONFIG_DIR"
    echo "$1" > "$XRAY_CONFIG_PATH"
    chmod 644 "$XRAY_CONFIG_PATH"
    ok "xray 配置已写入 $XRAY_CONFIG_PATH"
}

# ── 订阅链接与状态扩展 ───────────────────────────────
default_ip_urls_json() {
    printf '%s\n' "${DEFAULT_IP_URLS[@]}" | jq -R . | jq -s -c .
}

state_get_sub_base() {
    local state="${1:-}"
    [[ -n "$state" ]] || state=$(load_state 2>/dev/null || true)
    local val=""
    if [[ -n "$state" ]]; then
        val=$(echo "$state" | jq -r '.sub_base // empty' 2>/dev/null | tr -d '\r' || true)
    fi
    while [[ "$val" == */ ]]; do
        val="${val%/}"
    done
    [[ -n "$val" ]] || val="$DEFAULT_SUB_BASE"
    echo "$val"
}

state_get_sub_token() {
    local state="${1:-}"
    [[ -n "$state" ]] || state=$(load_state 2>/dev/null || true)
    local val=""
    if [[ -n "$state" ]]; then
        val=$(echo "$state" | jq -r '.sub_token // ""' 2>/dev/null | tr -d '\r' || true)
    fi
    echo "$val"
}

state_get_port_mode() {
    local state="${1:-}"
    [[ -n "$state" ]] || state=$(load_state 2>/dev/null || true)
    local val=""
    if [[ -n "$state" ]]; then
        val=$(echo "$state" | jq -r '.port_mode // "all_tls"' 2>/dev/null | tr -d '\r' || true)
    fi
    case "$val" in
        all_tls|only_443) echo "$val" ;;
        *) echo "all_tls" ;;
    esac
}

state_get_ip_urls_json() {
    local state="${1:-}"
    [[ -n "$state" ]] || state=$(load_state 2>/dev/null || true)
    if [[ -n "$state" ]] && echo "$state" | jq -e '(.ip_urls | type == "array") and ((.ip_urls | length) > 0)' &>/dev/null; then
        echo "$state" | jq -c '.ip_urls'
        return
    fi
    default_ip_urls_json
}

ensure_state_sub_fields() {
    local st_json="$1"
    local def_ipu
    def_ipu=$(default_ip_urls_json)
    echo "$st_json" | jq --arg dsb "$DEFAULT_SUB_BASE" --argjson dipu "$def_ipu" '
        .sub_base = (if (.sub_base // "") != "" then (.sub_base | sub("/+$"; "")) else $dsb end) |
        .sub_token = (.sub_token // "") |
        .port_mode = (if (.port_mode == "only_443" or .port_mode == "all_tls") then .port_mode else "all_tls" end) |
        .ip_urls = (if (.ip_urls | type == "array") and ((.ip_urls | length) > 0) then .ip_urls else $dipu end)
    '
}

ensure_sub_token_present() {
    local state="$1" token
    [[ -n "$state" ]] || return 0
    token=$(echo "$state" | jq -r '.sub_token // ""' 2>/dev/null | tr -d '\r')
    [[ -n "$token" ]] && return 0
    token=$(gen_uuid | tr -d '-')
    state=$(echo "$state" | jq --arg t "$token" '.sub_token = $t')
    save_state "$state"
    info "已自动生成订阅密钥: $token"
}

build_link() {
    local uid="$1" domain="$2" proto="$3" path="$4"
    local sub_base="${5:-}"
    [[ -n "$sub_base" ]] || sub_base=$(state_get_sub_base)
    while [[ "$sub_base" == */ ]]; do
        sub_base="${sub_base%/}"
    done
    [[ -n "$sub_base" ]] || sub_base="$DEFAULT_SUB_BASE"
    local sub_token
    if [[ $# -ge 6 ]]; then
        sub_token="$6"
    else
        sub_token=$(state_get_sub_token)
    fi
    local ev="no" et="no" evm="no"
    case "$proto" in vless) ev="yes";; trojan) et="yes";; vmess) evm="yes";; esac
    local port_mode ip_urls ip_param=""
    port_mode=$(state_get_port_mode)
    ip_urls=$(load_state 2>/dev/null | jq -r '(.ip_urls // []) | join(",")' 2>/dev/null | tr -d '\r' || true)
    [[ -n "$ip_urls" ]] && ip_param="&ip_urls=$(urlencode "$ip_urls")"
    local url="${sub_base}/${uid}/sub?domain=${domain}&ev=${ev}&et=${et}&mess=${evm}&path=$(urlencode "$path")&port_mode=${port_mode}${ip_param}"
    if [[ -n "$sub_token" ]]; then
        url="${url}&token=$(urlencode "$sub_token")"
    fi
    echo "$url"
}

gen_all_links() {
    local uid="$1" domain="$2" routes_json="$3"
    local sub_base="${4:-}"
    [[ -n "$sub_base" ]] || sub_base=$(state_get_sub_base)
    local sub_token
    if [[ $# -ge 5 ]]; then
        sub_token="$5"
    else
        sub_token=$(state_get_sub_token)
    fi
    local links_json='{}'
    local proto path link
    while IFS=$'\t' read -r proto path; do
        link=$(build_link "$uid" "$domain" "$proto" "$path" "$sub_base" "$sub_token")
        links_json=$(echo "$links_json" | jq --arg p "$proto" --arg l "$link" '. + {($p):$l}')
    done < <(echo "$routes_json" | jq -r '.[] | [.protocol, .path] | @tsv' | tr -d '\r')
    echo "$links_json"
}

# ── 本地优选 IP 拉取与订阅生成 ────────────────────────
is_valid_preferred_host() {
    local h="$1"
    if [[ "$h" =~ ^\[([0-9a-fA-F:]+)\]$ ]]; then
        local inner="${BASH_REMATCH[1]}"
        [[ "$inner" == *:* ]] && return 0
        return 1
    fi
    if [[ "$h" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        local o1="${BASH_REMATCH[1]}" o2="${BASH_REMATCH[2]}" o3="${BASH_REMATCH[3]}" o4="${BASH_REMATCH[4]}"
        (( 10#$o1 <= 255 && 10#$o2 <= 255 && 10#$o3 <= 255 && 10#$o4 <= 255 )) && return 0
        return 1
    fi
    if [[ "$h" == *.* && "$h" != *..* && "$h" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]]; then
        [[ "$h" =~ [a-zA-Z] ]] && return 0
    fi
    return 1
}

fetch_and_clean_preferred_ips() {
    local state="${1:-}"
    [[ -n "$state" ]] || state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || die "未检测到部署"

    local domain port_mode ip_urls_json
    domain=$(echo "$state" | jq -r '.domain // ""' | tr -d '\r')
    [[ -n "$domain" ]] || die "state.json 缺少 domain 字段"
    port_mode=$(state_get_port_mode "$state")
    ip_urls_json=$(state_get_ip_urls_json "$state")

    declare -A seen_endpoint=()
    printf '%s\t%s\t%s\n' "$domain" "443" "原生地址-${domain}"
    seen_endpoint["${domain,,}:443"]=1

    local urls=() url
    mapfile -t urls < <(echo "$ip_urls_json" | jq -r '.[]' | tr -d '\r')

    for url in "${urls[@]}"; do
        [[ -n "$url" ]] || continue
        local content=""
        if ! content=$(curl -fsSL --connect-timeout 6 --max-time 15 "$url" 2>/dev/null); then
            info "警告: 拉取失败 $url (已跳过)"
            continue
        fi

        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line//$'\r'/}"
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            [[ -z "$line" ]] && continue
            [[ "$line" == \#* || "$line" == //* ]] && continue

            local addr_part="$line" raw_remark=""
            if [[ "$line" == *#* ]]; then
                addr_part="${line%%#*}"
                raw_remark="${line#*#}"
            fi
            addr_part="${addr_part#"${addr_part%%[![:space:]]*}"}"
            addr_part="${addr_part%"${addr_part##*[![:space:]]}"}"
            raw_remark="${raw_remark#"${raw_remark%%[![:space:]]*}"}"
            raw_remark="${raw_remark%"${raw_remark##*[![:space:]]}"}"

            [[ -z "$addr_part" ]] && continue
            [[ "$addr_part" == *"://"* ]] && continue
            if [[ "$raw_remark" == *"▼"* || "$raw_remark" == *"▲"* || "$raw_remark" == *"分享优选网"* || "$raw_remark" == *"分享免费优选网"* ]]; then
                continue
            fi

            if [[ "$addr_part" == *,* ]]; then
                addr_part="${addr_part%%,*}"
                addr_part="${addr_part%"${addr_part##*[![:space:]]}"}"
                [[ -z "$addr_part" ]] && continue
            fi

            local host="" port="443"
            if [[ "$addr_part" =~ ^\[([0-9a-fA-F:]+)\]:([0-9]+)$ ]]; then
                host="[${BASH_REMATCH[1]}]"
                port="${BASH_REMATCH[2]}"
            elif [[ "$addr_part" =~ ^\[([0-9a-fA-F:]+)\]$ ]]; then
                host="[${BASH_REMATCH[1]}]"
                port="443"
            elif [[ "$addr_part" == \[* ]]; then
                continue
            elif [[ "$addr_part" =~ ^([^:]+):([0-9]+)$ ]]; then
                host="${BASH_REMATCH[1]}"
                port="${BASH_REMATCH[2]}"
            elif [[ "$addr_part" == *:* ]]; then
                continue
            else
                host="$addr_part"
                port="443"
            fi

            is_valid_preferred_host "$host" || continue

            if [[ "$port_mode" == "only_443" ]]; then
                [[ "$port" == "443" ]] || continue
            else
                case "$port" in
                    443|2053|2083|2087|2096|8443) ;;
                    *) continue ;;
                esac
            fi

            local ep_key="${host,,}:${port}"
            [[ -n "${seen_endpoint[$ep_key]:-}" ]] && continue
            seen_endpoint["$ep_key"]=1

            raw_remark="${raw_remark//$'\t'/ }"
            raw_remark=$(printf '%s' "$raw_remark" | tr -d '\000-\037\177')
            [[ -n "$raw_remark" ]] || raw_remark="${host}:${port}"

            printf '%s\t%s\t%s\n' "$host" "$port" "$raw_remark"
        done < <(printf '%s' "$content")
    done
}

generate_local_subscriptions() {
    local state
    state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || die "未检测到部署"

    local domain uid routes_json port_mode
    domain=$(echo "$state" | jq -r '.domain // ""' | tr -d '\r')
    uid=$(echo "$state" | jq -r '.uuid // ""' | tr -d '\r')
    routes_json=$(echo "$state" | jq -c '.routes // []' | tr -d '\r')
    port_mode=$(state_get_port_mode "$state")
    [[ -n "$domain" && -n "$uid" ]] || die "state.json 缺少 domain 或 uuid"

    info "正在拉取并清洗优选 IP（端口策略: $port_mode）..."
    local cleaned_tsv
    cleaned_tsv=$(fetch_and_clean_preferred_ips "$state")
    local endpoint_count
    endpoint_count=$(printf '%s\n' "$cleaned_tsv" | grep -c . || true)

    mkdir -p "$STATE_DIR" "$LOCAL_SUB_DIR"
    chmod 700 "$STATE_DIR" "$LOCAL_SUB_DIR"
    rm -f "$LOCAL_SUB_DIR"/nodes_*.txt "$LOCAL_SUB_DIR"/sub_*_base64.txt
    : > "$LOCAL_SUB_DIR/nodes_all.txt"

    local proto_rows=() row enabled_protos=()
    mapfile -t proto_rows < <(echo "$routes_json" | jq -r '.[] | [.protocol, .path] | @tsv' | tr -d '\r')
    [[ ${#proto_rows[@]} -gt 0 ]] || die "未找到已启用协议配置"

    for row in "${proto_rows[@]}"; do
        local proto="${row%%$'\t'*}"
        local path="${row#*$'\t'}"
        local proto_nodes_file="$LOCAL_SUB_DIR/nodes_${proto}.txt"
        local proto_b64_file="$LOCAL_SUB_DIR/sub_${proto}_base64.txt"

        printf '%s\n' "$cleaned_tsv" | jq -R -s -r \
            --arg uid "$uid" --arg domain "$domain" --arg path "$path" --arg proto "$proto" '
            split("\n")
            | map(select(length > 0) | split("\t"))
            | .[]
            | .[0] as $uri_host
            | (.[0] | sub("^\\["; "") | sub("\\]$"; "")) as $raw_host
            | .[1] as $port
            | .[2] as $remark
            | if $proto == "vless" then
                "vless://" + $uid + "@" + $uri_host + ":" + $port
                + "?encryption=none&security=tls&sni=" + ($domain | @uri)
                + "&fp=chrome&type=ws&host=" + ($domain | @uri)
                + "&path=" + ($path | @uri) + "#" + ($remark | @uri)
              elif $proto == "trojan" then
                "trojan://" + $uid + "@" + $uri_host + ":" + $port
                + "?security=tls&sni=" + ($domain | @uri)
                + "&fp=chrome&type=ws&host=" + ($domain | @uri)
                + "&path=" + ($path | @uri) + "#" + ($remark | @uri)
              elif $proto == "vmess" then
                "vmess://" + ({
                    v: "2",
                    ps: ($remark + "-VMess-WS-TLS"),
                    add: $raw_host,
                    port: $port,
                    id: $uid,
                    aid: "0",
                    scy: "auto",
                    net: "ws",
                    type: "none",
                    host: $domain,
                    path: $path,
                    tls: "tls",
                    sni: $domain,
                    fp: "chrome"
                } | tojson | @base64)
              else
                empty
              end
        ' | tr -d '\r' > "$proto_nodes_file"

        cat "$proto_nodes_file" >> "$LOCAL_SUB_DIR/nodes_all.txt"
        jq -Rsr '@base64' < "$proto_nodes_file" | tr -d '\r' > "$proto_b64_file"
        chmod 600 "$proto_nodes_file" "$proto_b64_file"
        enabled_protos+=("$proto")
    done

    jq -Rsr '@base64' < "$LOCAL_SUB_DIR/nodes_all.txt" | tr -d '\r' > "$LOCAL_SUB_DIR/sub_all_base64.txt"
    chmod 600 "$LOCAL_SUB_DIR/nodes_all.txt" "$LOCAL_SUB_DIR/sub_all_base64.txt"

    local updated_at links_json new_state total_nodes
    updated_at=$(date '+%Y-%m-%d %H:%M:%S')
    total_nodes=$(wc -l < "$LOCAL_SUB_DIR/nodes_all.txt" | tr -d ' ')
    links_json=$(gen_all_links "$uid" "$domain" "$routes_json" "$(state_get_sub_base "$state")" "$(state_get_sub_token "$state")")
    save_links_snapshot "$domain" "$uid" "$links_json"

    new_state=$(echo "$state" | jq \
        --argjson cnt "$endpoint_count" \
        --arg ts "$updated_at" \
        --argjson l "$links_json" \
        '.local_sub_count=$cnt | .local_sub_updated_at=$ts | .links=$l')
    save_state "$(ensure_state_sub_fields "$new_state")"

    echo
    ok "本地优选订阅生成完成"
    echo "  域名: $domain"
    echo "  唯一优选地址数: $endpoint_count  (端口策略: $port_mode)"
    echo "  启用协议: ${enabled_protos[*]}  总节点数: $total_nodes"
    echo "  更新时间: $updated_at"
    echo
    echo "  汇总 Base64 订阅: $LOCAL_SUB_DIR/sub_all_base64.txt"
    echo "  汇总原始节点:     $LOCAL_SUB_DIR/nodes_all.txt"
    for p in "${enabled_protos[@]}"; do
        echo "  [$p] 节点: $LOCAL_SUB_DIR/nodes_${p}.txt | Base64: $LOCAL_SUB_DIR/sub_${p}_base64.txt"
    done
    echo
    echo "原始节点预览 (前 5 条):"
    head -n 5 "$LOCAL_SUB_DIR/nodes_all.txt" | sed 's/^/  /'
    if [[ "$total_nodes" -gt 5 ]]; then
        echo "  ... 共 $total_nodes 条，完整列表见 $LOCAL_SUB_DIR/nodes_all.txt"
    fi
    echo
    echo "── 一键复制 Base64 订阅 (sub_all_base64.txt) ──"
    cat "$LOCAL_SUB_DIR/sub_all_base64.txt"
    echo
    echo "────────────────────────────────────────────────"
}

# ── 状态 ──────────────────────────────────────────────
load_state() { [[ -f "$STATE_PATH" ]] && cat "$STATE_PATH"; }
save_state() { mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"; echo "$1" > "$STATE_PATH"; chmod 600 "$STATE_PATH"; }
remove_state() { rm -f "$STATE_PATH"; }

save_links_snapshot() {
    local domain="$1" uid="$2" links_json="$3"
    mkdir -p "$(dirname "$LAST_LINKS_PATH")"
    { echo "域名: $domain"; echo "UUID: $uid"; echo
      echo "$links_json" | jq -r 'to_entries[] | "\(.key) \(.value)"'
    } | tr -d '\r' > "$LAST_LINKS_PATH"
    chmod 600 "$LAST_LINKS_PATH"
}

print_links() {
    local links_json="$1"
    local proto link
    while IFS=$'\t' read -r proto link; do
        echo "  ${PROTO_LABEL[$proto]:-$proto}订阅 $link"
    done < <(echo "$links_json" | jq -r 'to_entries[] | [.key, .value] | @tsv')
}

refresh_links_after_sub_change() {
    local state="$1"
    [[ -n "$state" ]] || return 0
    local domain uid routes_json links_json
    domain=$(echo "$state" | jq -r '.domain // empty' 2>/dev/null | tr -d '\r' || true)
    uid=$(echo "$state" | jq -r '.uuid // empty' 2>/dev/null | tr -d '\r' || true)
    routes_json=$(echo "$state" | jq -c '.routes // []' 2>/dev/null | tr -d '\r' || true)
    [[ -n "$domain" && -n "$uid" ]] || return 0
    links_json=$(gen_all_links "$uid" "$domain" "$routes_json" "$(state_get_sub_base "$state")" "$(state_get_sub_token "$state")")
    save_links_snapshot "$domain" "$uid" "$links_json"
    save_state "$(echo "$state" | jq --argjson l "$links_json" '.links=$l')"
    print_links "$links_json"
    echo "若使用 CF Worker 订阅，请将新链接更新至客户端；若使用 VPS 直连订阅则无需更换链接"
}

# ── 交互辅助 ─────────────────────────────────────────
prompt_protocols() {
    read -rp "创建协议(1=vless,2=trojan,3=vmess，逗号分隔，留空=全部): " proto_raw
    local protocols=()
    if [[ -z "$proto_raw" ]]; then
        protocols=(vless trojan vmess)
    else
        local -A pmap=([1]=vless [2]=trojan [3]=vmess [vless]=vless [trojan]=trojan [vmess]=vmess)
        IFS=',' read -ra tokens <<< "$proto_raw"
        for t in "${tokens[@]}"; do
            t="${t,,}"; t="${t// /}"
            [[ -n "${pmap[$t]:-}" ]] || die "未知协议: $t"
            protocols+=("${pmap[$t]}")
        done
    fi
    echo "${protocols[@]}"
}

prompt_uuid() {
    local uid
    read -rp "UUID(留空=自动生成): " custom_uuid
    if [[ -n "$custom_uuid" ]]; then
        [[ "$custom_uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || die "UUID 格式不正确"
        uid="${custom_uuid,,}"
    else
        uid=$(gen_uuid)
    fi
    echo "$uid"
}

prompt_path_prefix() {
    local default="$1"
    read -rp "WS 路径前缀(留空=/${default}): " pfx
    [[ -z "$pfx" ]] && pfx="/${default}"
    [[ "$pfx" == /* ]] || pfx="/${pfx}"
    echo "$pfx"
}

# 生成路由 JSON，NAT 和直连通用
# NAT 时 xray 监听 listen_port(内部)，CF 转发到 cf_port(外部)
# 直连时 listen_port == cf_port
build_routes() {
    local net_mode="$1" path_prefix="$2" proto_count="$3"
    shift 3
    local protocols=("$@")

    local routes_json='[]'

    if [[ "$net_mode" == "nat" ]]; then
        echo >&2
        info "NAT 模式: 逐个配置每个协议的端口映射" >&2
        echo >&2

        for proto in "${protocols[@]}"; do
            local int_port ext_port
            read -rp "${proto} 内部监听端口(xray监听): " int_port
            [[ "$int_port" =~ ^[0-9]+$ ]] || die "无效端口: $int_port"
            read -rp "${proto} 外部映射端口(对外暴露): " ext_port
            [[ "$ext_port" =~ ^[0-9]+$ ]] || die "无效端口: $ext_port"
            local path="${path_prefix}-${PROTO_SUFFIX[$proto]}"
            routes_json=$(echo "$routes_json" | jq \
                --arg p "$proto" --argjson lp "$((int_port))" --argjson cp "$((ext_port))" --arg pa "$path" \
                '. + [{protocol:$p, listen_port:$lp, cf_port:$cp, path:$pa}]')
        done
    else
        read -rp "自定义端口?(逗号分隔，留空=随机): " custom_ports_raw
        local existing_ports
        existing_ports=$(get_listening_ports)
        local custom_ports=()
        if [[ -n "$custom_ports_raw" ]]; then
            IFS=',' read -ra custom_ports <<< "$custom_ports_raw"
            [[ ${#custom_ports[@]} -eq $proto_count ]] || die "端口数量与协议数不一致"
        fi

        local pi=0
        for proto in "${protocols[@]}"; do
            local port
            if [[ ${#custom_ports[@]} -gt 0 ]]; then
                port="${custom_ports[$pi]// /}"
                [[ "$port" =~ ^[0-9]+$ ]] || die "无效端口: $port"
            else
                port=$(rand_port "$existing_ports")
            fi
            existing_ports="$existing_ports $port"
            local path="${path_prefix}-${PROTO_SUFFIX[$proto]}"
            routes_json=$(echo "$routes_json" | jq \
                --arg p "$proto" --argjson lp "$((port))" --arg pa "$path" \
                '. + [{protocol:$p, listen_port:$lp, cf_port:$lp, path:$pa}]')
            pi=$((pi + 1))
        done
    fi

    echo "$routes_json"
}

# ── 1. 安装 ──────────────────────────────────────────
do_install() {
    local state
    state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] && die "检测到上次配置($(echo "$state" | jq -r '.domain // "?"'))，请先卸载"

    [[ -f "$XRAY_BINARY" ]] && ok "xray-core 已安装" || install_xray

    local net_mode
    net_mode=$(prompt_net_mode "$(detect_nat)")
    ok "网络模式: $(net_mode_label "$net_mode")"

    prompt_cf

    # 输入域名并校验能匹配到 CF Zone，失败可重输
    local domain zone_id
    while true; do
        read -rp "绑定域名: " domain || die "输入已中断"
        if [[ -z "$domain" ]]; then
            echo "域名不能为空，请重试"
            continue
        fi
        if zone_id=$(cf_find_zone "$domain"); then
            info "匹配到 Zone: $zone_id"
            break
        fi
        echo "无法在该 CF 账号下匹配 Zone: $domain，请确认域名已托管并重输（Ctrl+C 退出）"
    done

    local protocols_str
    protocols_str=$(prompt_protocols)
    read -ra protocols <<< "$protocols_str"

    local uid
    uid=$(prompt_uuid)
    local short_id="${uid:0:8}"
    local path_prefix
    path_prefix=$(prompt_path_prefix "$short_id")

    local routes_json
    routes_json=$(build_routes "$net_mode" "$path_prefix" "${#protocols[@]}" "${protocols[@]}")

    # 预览
    echo
    echo "配置预览:"
    echo "  域名:  $domain"
    echo "  UUID:  $uid"
    echo "  模式:  $net_mode"
    echo "$routes_json" | jq -r '.[] | "  \(.protocol)  监听:\(.listen_port)  CF端口:\(.cf_port)  路径:\(.path)"'
    echo
    read -rp "确认部署? (Y/n): " confirm
    [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || die "已取消"

    # xray
    local config
    config=$(gen_xray_config "$routes_json" "$uid")
    write_xray_config "$config"
    [[ "$INIT_SYSTEM" == "openrc" && ! -f "$XRAY_OPENRC_SCRIPT" ]] && write_openrc_script && ok "OpenRC 服务脚本已创建"
    restart_xray

    # CF
    local public_ip dns_before ssl_before origin_rules_before dns_record_id
    public_ip=$(get_public_ip)
    dns_before=$(cf_get_dns "$zone_id" "$domain" || echo "null")
    [[ "$dns_before" == "" ]] && dns_before="null"
    ssl_before=$(cf_get_ssl "$zone_id")
    origin_rules_before=$(cf_get_origin_rules "$zone_id")

    dns_record_id=$(cf_upsert_dns "$zone_id" "$domain" "$public_ip")
    ok "DNS A 记录: $domain -> $public_ip (已代理)"
    cf_set_ssl "$zone_id" "flexible"
    ok "SSL 模式: flexible"
    apply_origin_rules "$zone_id" "$domain" "$routes_json"
    ok "Origin Rules: ${#protocols[@]} 条"

    # 安全规则：关闭可能拦截 WS 的设置
    local security_backup
    security_backup=$(cf_relax_security "$zone_id")

    # 订阅
    local init_sub_base="$DEFAULT_SUB_BASE" init_sub_token="" init_port_mode="all_tls" init_ip_urls
    init_ip_urls=$(default_ip_urls_json)
    local links_json
    links_json=$(gen_all_links "$uid" "$domain" "$routes_json" "$init_sub_base" "$init_sub_token")
    save_links_snapshot "$domain" "$uid" "$links_json"

    # 状态
    local dns_existed="false"
    [[ "$dns_before" != "null" ]] && dns_existed="true"
    # jq --argjson 遇到空串会整体失败，导致 state.json 存不下来（存不下就没法改配置/卸载）。
    # CF 接口任何一个返回空都不该拖垮状态保存，这里统一兜底成合法 JSON。
    [[ -n "$dns_before" ]]          || dns_before="null"
    [[ -n "$origin_rules_before" ]] || origin_rules_before="[]"
    [[ -n "$security_backup" ]]     || security_backup="null"
    [[ -n "$links_json" ]]          || links_json="{}"
    [[ -n "$routes_json" ]]         || routes_json="[]"
    save_state "$(jq -n \
        --arg d "$domain" --arg z "$zone_id" --arg u "$uid" --arg s "$short_id" --arg mode "$net_mode" \
        --argjson routes "$routes_json" \
        --arg drid "$dns_record_id" --argjson dex "$dns_existed" --argjson drec "$dns_before" \
        --arg ssl "$ssl_before" --argjson orbk "$origin_rules_before" --argjson links "$links_json" \
        --argjson secbk "$security_backup" \
        --arg sb "$init_sub_base" --arg st "$init_sub_token" --arg pm "$init_port_mode" --argjson ipu "$init_ip_urls" \
        '{domain:$d,zone_id:$z,uuid:$u,short_id:$s,net_mode:$mode,routes:$routes,
          managed_dns_record_id:$drid,dns_backup:{existed:$dex,record:$drec},
          ssl_backup:$ssl,origin_rules_backup:$orbk,security_backup:$secbk,links:$links,
          sub_base:$sb,sub_token:$st,port_mode:$pm,ip_urls:$ipu}')"

    echo
    ok "部署完成"
    print_links "$links_json"
    echo
    echo "订阅已保存到 $LAST_LINKS_PATH"
}

# ── 2. 卸载 ──────────────────────────────────────────
do_uninstall() {
    local state
    state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || die "未检测到上次配置"

    local domain; domain=$(echo "$state" | jq -r '.domain')
    echo "正在卸载: $domain"

    stop_xray; rm -f "$XRAY_CONFIG_PATH"
    ok "xray 已停止"

    if load_cf_account; then
        local zone_id; zone_id=$(echo "$state" | jq -r '.zone_id // ""')
        if [[ -n "$zone_id" ]]; then
            cf_put_origin_rules "$zone_id" "$(echo "$state" | jq '.origin_rules_backup // []')"
            ok "Origin Rules 已恢复"

            local ssl_bk; ssl_bk=$(echo "$state" | jq -r '.ssl_backup // ""')
            [[ -n "$ssl_bk" ]] && cf_set_ssl "$zone_id" "$ssl_bk" && ok "SSL: $ssl_bk"

            local dns_existed record_id
            dns_existed=$(echo "$state" | jq -r '.dns_backup.existed')
            record_id=$(echo "$state" | jq -r '.managed_dns_record_id // ""')
            if [[ "$dns_existed" == "true" ]]; then
                local rp; rp=$(echo "$state" | jq '.dns_backup.record | {type:(.type//"A"),name:(.name//""),content:(.content//""),proxied:(.proxied//false),ttl:(.ttl//1)}')
                cf_call PUT "/zones/${zone_id}/dns_records/${record_id}" "$rp" >/dev/null
                ok "DNS 已恢复"
            elif [[ -n "$record_id" ]]; then
                cf_call_raw DELETE "/zones/${zone_id}/dns_records/${record_id}" >/dev/null 2>&1 || true
                ok "DNS 已删除"
            fi
            # 恢复安全规则
            local sec_bk; sec_bk=$(echo "$state" | jq '.security_backup // null')
            cf_restore_security "$zone_id" "$sec_bk"
        fi
    else
        echo "无 CF 凭据，跳过恢复"
    fi

    local_sub_cleanup
    remove_state
    rm -f "$LAST_LINKS_PATH" "$CF_ACCOUNT_PATH"
    rm -rf "$LOCAL_SUB_DIR"
    rm -f "$LOCAL_SCRIPT_PATH"
    ok "已清理订阅快照、本地优选订阅、CF 凭据、直连订阅服务与本地离线脚本"
    ok "卸载完成"
}

# ── 3. 查看订阅 ──────────────────────────────────────
do_show() {
    local state; state=$(load_state 2>/dev/null || true)
    if [[ -n "$state" ]]; then
        local domain uid links_json local_sub_url
        domain=$(echo "$state" | jq -r '.domain // ""' | tr -d '\r')
        uid=$(echo "$state" | jq -r '.uuid // ""' | tr -d '\r')
        links_json=$(echo "$state" | jq '.links // {}' | tr -d '\r')
        local_sub_url=$(echo "$state" | jq -r '.local_sub_url // ""' | tr -d '\r')
        if [[ -f "$LAST_LINKS_PATH" ]]; then
            save_links_snapshot "$domain" "$uid" "$links_json"
        fi
        echo "域名: $domain"
        echo "UUID: $uid"
        echo "直连订阅: ${local_sub_url:-未安装 (菜单 9 -> 6)}"
        echo "远程订阅 (可选):"
        echo "$links_json" | jq -r 'to_entries[] | "\(.key) \(.value)"'
        if [[ -f "$LOCAL_SUB_DIR/sub_all_base64.txt" ]]; then
            local sub_cnt sub_time
            sub_cnt=$(echo "$state" | jq -r '.local_sub_count // 0' | tr -d '\r')
            sub_time=$(echo "$state" | jq -r '.local_sub_updated_at // "未知"' | tr -d '\r')
            echo
            echo "导出的节点文件:"
            echo "  优选地址数: $sub_cnt  更新时间: $sub_time"
            echo "  Base64 订阅文件: $LOCAL_SUB_DIR/sub_all_base64.txt"
            echo "  原始节点文件:    $LOCAL_SUB_DIR/nodes_all.txt"
            echo "  快速导出: cat $LOCAL_SUB_DIR/sub_all_base64.txt"
        fi
        return
    fi
    if [[ -f "$LAST_LINKS_PATH" ]]; then cat "$LAST_LINKS_PATH"; return; fi
    die "无历史订阅"
}

# ── 4. 修改配置 ──────────────────────────────────────
do_modify() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || die "未检测到部署"

    local domain uid routes_json net_mode
    domain=$(echo "$state" | jq -r '.domain')
    uid=$(echo "$state" | jq -r '.uuid')
    routes_json=$(echo "$state" | jq '.routes')
    net_mode=$(echo "$state" | jq -r '.net_mode // "direct"')

    echo
    echo "当前配置 ($net_mode):"
    echo "  域名: $domain  UUID: $uid"
    echo "$routes_json" | jq -r '.[] | "  \(.protocol)  监听:\(.listen_port)  CF端口:\(.cf_port)  路径:\(.path)"'
    echo
    echo "  1. 修改 UUID"
    echo "  2. 修改端口"
    echo "  3. 修改 WS 路径"
    echo "  4. 全部修改"
    echo "  0. 返回"
    echo
    read -rp "请选择 [0-4]: " mc

    local new_uid="$uid" new_routes="$routes_json" changed=false

    [[ "$mc" =~ ^[0-4]$ ]] || die "无效选项"
    [[ "$mc" == "0" ]] && return

    if [[ "$mc" == "1" || "$mc" == "4" ]]; then
        read -rp "新 UUID(留空=重新生成): " iu
        if [[ -n "$iu" ]]; then
            [[ "$iu" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || die "UUID 格式不正确"
            new_uid="${iu,,}"
        else
            new_uid=$(gen_uuid)
        fi
        changed=true; ok "UUID: $new_uid"
    fi

    if [[ "$mc" == "2" || "$mc" == "4" ]]; then
        local pc; pc=$(echo "$new_routes" | jq 'length')
        if [[ "$net_mode" == "nat" ]]; then
            echo "当前映射: $(echo "$new_routes" | jq -r '[.[] | "\(.listen_port):\(.cf_port)"] | join(",")')"
            read -rp "新端口映射(内部:外部，共${pc}组，留空=不改): " mr
            if [[ -n "$mr" ]]; then
                IFS=',' read -ra maps <<< "$mr"
                [[ ${#maps[@]} -eq $pc ]] || die "数量不匹配"
                local idx=0
                for m in "${maps[@]}"; do
                    m="${m// /}"; local lp="${m%%:*}" cp="${m##*:}"
                    [[ "$lp" =~ ^[0-9]+$ && "$cp" =~ ^[0-9]+$ ]] || die "无效: $m"
                    new_routes=$(echo "$new_routes" | jq --argjson i $idx --argjson l "$((lp))" --argjson c "$((cp))" '.[$i].listen_port=$l|.[$i].cf_port=$c')
                    idx=$((idx+1))
                done
                changed=true; ok "端口已更新"
            fi
        else
            echo "当前端口: $(echo "$new_routes" | jq -r '[.[].listen_port|tostring] | join(",")')"
            read -rp "新端口(逗号分隔，共${pc}个，留空=不改): " pr
            if [[ -n "$pr" ]]; then
                IFS=',' read -ra nps <<< "$pr"
                [[ ${#nps[@]} -eq $pc ]] || die "数量不匹配"
                local idx=0
                for np in "${nps[@]}"; do
                    np="${np// /}"; [[ "$np" =~ ^[0-9]+$ ]] || die "无效: $np"
                    new_routes=$(echo "$new_routes" | jq --argjson i $idx --argjson p "$((np))" '.[$i].listen_port=$p|.[$i].cf_port=$p')
                    idx=$((idx+1))
                done
                changed=true; ok "端口已更新"
            fi
        fi
    fi

    if [[ "$mc" == "3" || "$mc" == "4" ]]; then
        echo "当前路径: $(echo "$new_routes" | jq -r '[.[].path] | join(", ")')"
        read -rp "新 WS 路径前缀(留空=不改): " np
        if [[ -n "$np" ]]; then
            [[ "$np" == /* ]] || np="/${np}"
            new_routes=$(echo "$new_routes" | jq --arg pfx "$np" '[.[]|.path=($pfx+"-"+(if .protocol=="vless" then "vl" elif .protocol=="trojan" then "tr" else "vm" end))]')
            changed=true; ok "路径已更新"
        fi
    fi

    [[ "$changed" == "true" ]] || { echo "无修改"; return; }

    write_xray_config "$(gen_xray_config "$new_routes" "$new_uid")"
    restart_xray

    if load_cf_account; then
        apply_origin_rules "$(echo "$state" | jq -r '.zone_id')" "$domain" "$new_routes"
        ok "Origin Rules 已更新"
    fi

    local links_json; links_json=$(gen_all_links "$new_uid" "$domain" "$new_routes" "$(state_get_sub_base "$state")" "$(state_get_sub_token "$state")")
    save_links_snapshot "$domain" "$new_uid" "$links_json"
    local updated_state
    updated_state=$(echo "$state" | jq --arg u "$new_uid" --argjson r "$new_routes" --argjson l "$links_json" --arg s "${new_uid:0:8}" \
        '.uuid=$u|.short_id=$s|.routes=$r|.links=$l')
    save_state "$(ensure_state_sub_fields "$updated_state")"

    echo; ok "配置已更新"; print_links "$links_json"
}

# ── 5. 查看当前配置 ──────────────────────────────────
do_show_config() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || die "未检测到部署"

    ensure_sub_token_present "$state"
    state=$(load_state 2>/dev/null || true)

    local sub_base sub_token ip_count port_mode port_label local_sub_url
    local_sub_url=$(echo "$state" | jq -r '.local_sub_url // ""' | tr -d '\r')
    sub_base=$(state_get_sub_base "$state")
    sub_token=$(state_get_sub_token "$state")
    ip_count=$(state_get_ip_urls_json "$state" | jq 'length' | tr -d '\r')
    port_mode=$(state_get_port_mode "$state")
    [[ "$port_mode" == "only_443" ]] && port_label="only_443 (仅443)" || port_label="all_tls (全部CF TLS端口)"

    echo
    echo "域名:  $(echo "$state" | jq -r '.domain')"
    echo "UUID:  $(echo "$state" | jq -r '.uuid')"
    echo "模式:  $(echo "$state" | jq -r '.net_mode // "direct"')"
    echo "直连订阅: ${local_sub_url:-未安装 (菜单 9 -> 6)}"
    echo
    echo "入站:"
    echo "$state" | jq -r '.routes[] | "  \(.protocol)  监听:\(.listen_port)  CF端口:\(.cf_port)  路径:\(.path)"'
    echo
    echo -n "xray: "; svc_is_active && echo "运行中" || echo "未运行"
    echo
    echo "远程订阅 (可选): $sub_base"
    echo "访问密钥: ${sub_token:-(未设置)}"
    echo "优选配置: 优选源=${ip_count}个  端口策略=${port_label}"
    if [[ -f "$LOCAL_SUB_DIR/sub_all_base64.txt" ]]; then
        local lcnt ltime
        lcnt=$(echo "$state" | jq -r '.local_sub_count // 0' | tr -d '\r')
        ltime=$(echo "$state" | jq -r '.local_sub_updated_at // "未知"' | tr -d '\r')
        echo "导出的节点文件: 已生成 (${lcnt}个优选地址, 更新于 ${ltime})"
        echo "                $LOCAL_SUB_DIR/sub_all_base64.txt"
    else
        echo "导出的节点文件: 未生成 (可通过菜单 9 -> 1 生成)"
    fi
    echo
    echo "远程订阅链接:"
    local links_json
    links_json=$(echo "$state" | jq -c '.links // {}')
    if [[ "$(echo "$links_json" | jq 'length')" == "0" ]]; then
        echo "  (无订阅链接，可进入菜单 9 刷新生成)"
    else
        print_links "$links_json"
    fi
    echo
}

# ── 6. 更新外部端口（NAT 快捷操作）──────────────────
do_update_ports() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || die "未检测到部署"

    local domain routes_json net_mode
    domain=$(echo "$state" | jq -r '.domain')
    routes_json=$(echo "$state" | jq '.routes')
    net_mode=$(echo "$state" | jq -r '.net_mode // "direct"')

    echo
    echo "当前端口映射:"
    echo "$routes_json" | jq -r '.[] | "  \(.protocol)  监听:\(.listen_port) -> 外部:\(.cf_port)"'
    echo

    local pc; pc=$(echo "$routes_json" | jq 'length')

    if [[ "$net_mode" == "nat" ]]; then
        info "NAT 模式: 只更新外部端口(CF Origin Rules)，xray 监听端口不变"
        echo

        local new_routes="$routes_json" idx=0
        # 先把数据收进数组再循环：若用 `done < <(...)`，循环体的 stdin 会被数据流占用，
        # 里面的交互 read 会吃掉下一行数据。
        local rows=() row
        mapfile -t rows < <(echo "$routes_json" | jq -r '.[] | [.protocol, (.cf_port|tostring)] | @tsv')
        for row in "${rows[@]}"; do
            local proto="${row%%$'\t'*}" old_cp="${row##*$'\t'}" ne
            read -rp "${proto} 新外部端口(当前=${old_cp}): " ne
            [[ -n "$ne" ]] || die "不能为空"
            [[ "$ne" =~ ^[0-9]+$ ]] || die "无效端口: $ne"
            new_routes=$(echo "$new_routes" | jq --argjson i $idx --argjson p "$((ne))" '.[$i].cf_port=$p')
            idx=$((idx+1))
        done

        echo
        echo "更新预览:"
        echo "$new_routes" | jq -r '.[] | "  \(.protocol)  监听:\(.listen_port) -> 外部:\(.cf_port)"'
        read -rp "确认? (Y/n): " confirm
        [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || die "已取消"

        # 只更新 CF Origin Rules，不动 xray
        load_cf_account || die "未找到 CF 凭据"
        apply_origin_rules "$(echo "$state" | jq -r '.zone_id')" "$domain" "$new_routes"
        ok "Origin Rules 已更新"

        # 同时更新 DNS（公网 IP 可能也变了）
        local public_ip; public_ip=$(get_public_ip)
        local zone_id; zone_id=$(echo "$state" | jq -r '.zone_id')
        local current_dns; current_dns=$(cf_get_dns "$zone_id" "$domain")
        local current_ip; current_ip=$(echo "$current_dns" | jq -r '.content // ""')
        if [[ "$current_ip" != "$public_ip" ]]; then
            cf_upsert_dns "$zone_id" "$domain" "$public_ip" >/dev/null
            ok "DNS 已更新: $domain -> $public_ip"
        fi

        local uid; uid=$(echo "$state" | jq -r '.uuid')
        local links_json; links_json=$(gen_all_links "$uid" "$domain" "$new_routes" "$(state_get_sub_base "$state")" "$(state_get_sub_token "$state")")
        save_links_snapshot "$domain" "$uid" "$links_json"
        local updated_state
        updated_state=$(echo "$state" | jq --argjson r "$new_routes" --argjson l "$links_json" '.routes=$r|.links=$l')
        save_state "$(ensure_state_sub_fields "$updated_state")"

        echo; ok "外部端口已更新"; print_links "$links_json"
    else
        info "直连模式: 端口变更需要同时修改 xray 监听，请使用 [4.修改配置]"
    fi
}

# ── 7. 重启 xray ─────────────────────────────────────
# ── 8. 切换网络模式 ──────────────────────────────────
# 探测可能判错（issue #1），装完之后也得能改，否则只能卸载重装。
do_switch_net_mode() {
    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || die "未检测到部署"

    local domain zone_id uid cur routes_json
    domain=$(echo "$state" | jq -r '.domain')
    zone_id=$(echo "$state" | jq -r '.zone_id')
    uid=$(echo "$state" | jq -r '.uuid')
    cur=$(echo "$state" | jq -r '.net_mode // "direct"')
    routes_json=$(echo "$state" | jq '.routes')

    echo
    echo "当前模式: $(net_mode_label "$cur")"
    echo "$routes_json" | jq -r '.[] | "  \(.protocol)  监听:\(.listen_port)  外部:\(.cf_port)"'
    echo

    local target
    if [[ "$cur" == "nat" ]]; then
        target="direct"
        echo "切成直连后，对外端口将与 xray 监听端口一致。"
    else
        target="nat"
        echo "切成 NAT 后，需要为每个协议指定对外端口（路由器/宿主上映射到监听端口）。"
    fi
    read -rp "确认切换到 $(net_mode_label "$target")? (y/N): " c
    [[ "${c,,}" =~ ^(y|yes)$ ]] || die "已取消"

    local new_routes="$routes_json"
    if [[ "$target" == "direct" ]]; then
        # 直连下外部端口就是监听端口
        new_routes=$(echo "$new_routes" | jq '[.[] | .cf_port = .listen_port]')
    else
        local idx=0
        # 同上：先收进数组，别让数据流占住循环体的 stdin
        local rows=() row
        mapfile -t rows < <(echo "$routes_json" | jq -r '.[] | [.protocol, (.listen_port|tostring)] | @tsv')
        for row in "${rows[@]}"; do
            local proto="${row%%$'\t'*}" lp="${row##*$'\t'}" ep
            read -rp "${proto} 对外端口(监听=${lp}, 回车=相同): " ep
            [[ -n "$ep" ]] || ep="$lp"
            [[ "$ep" =~ ^[0-9]+$ ]] || die "无效端口: $ep"
            new_routes=$(echo "$new_routes" | jq --argjson i $idx --argjson p "$((ep))" '.[$i].cf_port=$p')
            idx=$((idx+1))
        done
    fi

    echo
    echo "更新预览:"
    echo "$new_routes" | jq -r '.[] | "  \(.protocol)  监听:\(.listen_port)  外部:\(.cf_port)"'
    read -rp "确认? (Y/n): " confirm
    [[ "${confirm,,}" =~ ^(|y|yes)$ ]] || die "已取消"

    load_cf_account || die "未找到 CF 凭据"
    apply_origin_rules "$zone_id" "$domain" "$new_routes"
    ok "Origin Rules 已更新"

    local links_json; links_json=$(gen_all_links "$uid" "$domain" "$new_routes" "$(state_get_sub_base "$state")" "$(state_get_sub_token "$state")")
    save_links_snapshot "$domain" "$uid" "$links_json"
    local updated_state
    updated_state=$(echo "$state" | jq --arg m "$target" --argjson r "$new_routes" --argjson l "$links_json" \
        '.net_mode=$m | .routes=$r | .links=$l')
    save_state "$(ensure_state_sub_fields "$updated_state")"

    echo; ok "已切换到 $(net_mode_label "$target")"; print_links "$links_json"
}

do_restart() {
    if ! svc_is_active; then
        echo "xray 当前未运行，正在启动..."
    else
        echo "正在重启 xray..."
    fi
    restart_xray
}

# ── 9. 订阅与优选 IP 管理（免 CF Key）─────────────────
write_shortcut_remote() {
    local url="$1"
    if ! is_safe_url "$url"; then
        info "拒绝写入不安全的脚本 URL: $url"
        return 1
    fi
    mkdir -p "$(dirname "$SHORTCUT_PATH")"
    local qurl
    qurl=$(printf '%q' "$url")
    {
        printf '#!/bin/bash\n'
        printf 'exec bash <(curl -fsSL %s) "$@"\n' "$qurl"
    } > "$SHORTCUT_PATH"
    chmod +x "$SHORTCUT_PATH"
    ok "快捷命令已更新 ($SHORTCUT_PATH -> $url)"
}

write_shortcut_local() {
    mkdir -p "$STATE_DIR" "$(dirname "$SHORTCUT_PATH")"
    chmod 700 "$STATE_DIR"
    local src="${BASH_SOURCE[0]:-}"
    if [[ -n "$src" && -f "$src" && "$src" != /dev/fd/* && "$src" != /proc/self/fd/* ]]; then
        cp "$src" "$LOCAL_SCRIPT_PATH"
    else
        if ! is_safe_url "$SCRIPT_RAW_URL"; then
            info "拒绝拉取不安全的脚本 URL: $SCRIPT_RAW_URL"
            return 1
        fi
        curl -fsSL "$SCRIPT_RAW_URL" -o "$LOCAL_SCRIPT_PATH" || { info "拉取离线副本失败: $SCRIPT_RAW_URL"; return 1; }
    fi
    bash -n "$LOCAL_SCRIPT_PATH" || { info "脚本语法校验失败，已中止固化"; return 1; }
    chmod 700 "$LOCAL_SCRIPT_PATH"
    local qpath
    qpath=$(printf '%q' "$LOCAL_SCRIPT_PATH")
    {
        printf '#!/bin/bash\n'
        printf 'exec bash %s "$@"\n' "$qpath"
    } > "$SHORTCUT_PATH"
    chmod +x "$SHORTCUT_PATH"
    ok "已固化为本地离线脚本 ($SHORTCUT_PATH -> $LOCAL_SCRIPT_PATH)"
}

# ── VPS 直连订阅服务（一键安装）─────────────────────
_port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

_port_listening() {
    local port="$1" hex
    if command -v ss &>/dev/null; then
        ss -ltn 2>/dev/null | awk -v p=":$port" 'NR>1 && substr($4, length($4)-length(p)+1) == p { f=1 } END { exit !f }'
        return
    fi
    hex=$(printf '%04X' "$port")
    awk -v h=":$hex" 'NR>1 && substr($2, length($2)-length(h)+1) == h && $4 == "0A" { f=1 } END { exit !f }' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

local_sub_wait_listen() {
    local port="$1" i
    for i in 1 2 3 4 5 6 7; do
        _port_listening "$port" && return 0
        sleep 0.5
    done
    return 1
}

local_sub_kill_strays() {
    local pids="" pid f
    if command -v pgrep &>/dev/null; then
        pids=$(pgrep -f -- "$LOCAL_SUB_PY" 2>/dev/null || true)
    else
        for f in /proc/[0-9]*/cmdline; do
            [[ -r "$f" ]] || continue
            tr '\0' ' ' < "$f" 2>/dev/null | grep -qF -- "$LOCAL_SUB_PY" || continue
            pid="${f#/proc/}"; pid="${pid%/cmdline}"
            pids="$pids $pid"
        done
    fi
    local alive=()
    for pid in $pids; do
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        [[ "$pid" == "$$" || "$pid" == "$PPID" ]] && continue
        kill "$pid" 2>/dev/null || true
        alive+=("$pid")
    done
    [[ "${#alive[@]}" -eq 0 ]] && return 0
    sleep 0.5
    for pid in "${alive[@]}"; do
        kill -0 "$pid" 2>/dev/null || continue
        kill -9 "$pid" 2>/dev/null || true
    done
    return 0
}

local_sub_stop_unit() {
    [[ "$SKIP_SERVICE" == "1" ]] && return 0
    local unit="$SYSTEMD_DIR/$LOCAL_SUB_SERVICE.service" initf="$INITD_DIR/$LOCAL_SUB_SERVICE"
    if [[ "$INIT_SYSTEM" == "systemd" && -f "$unit" ]]; then
        systemctl stop "$LOCAL_SUB_SERVICE" &>/dev/null || true
    fi
    if [[ -f "$initf" ]]; then
        rc-service "$LOCAL_SUB_SERVICE" stop &>/dev/null || true
    fi
    return 0
}

local_sub_start_unit() {
    [[ "$SKIP_SERVICE" == "1" ]] && return 0
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        systemctl start "$LOCAL_SUB_SERVICE" &>/dev/null || true
    else
        rc-service "$LOCAL_SUB_SERVICE" start &>/dev/null || true
    fi
    return 0
}

local_sub_server_active() {
    [[ "$SKIP_SERVICE" == "1" ]] && return 1
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl is-active --quiet "$LOCAL_SUB_SERVICE" &>/dev/null
    else rc-service "$LOCAL_SUB_SERVICE" status &>/dev/null 2>&1; fi
}

local_sub_cleanup() {
    local unit="$SYSTEMD_DIR/$LOCAL_SUB_SERVICE.service" initf="$INITD_DIR/$LOCAL_SUB_SERVICE"
    if [[ "$SKIP_SERVICE" != "1" ]]; then
        [[ -f "$unit" ]] && systemctl disable --now "$LOCAL_SUB_SERVICE" &>/dev/null || true
        if [[ -f "$initf" ]]; then
            rc-service "$LOCAL_SUB_SERVICE" stop &>/dev/null || true
            rc-update del "$LOCAL_SUB_SERVICE" default &>/dev/null || true
        fi
        [[ -f "$unit" ]] && systemctl daemon-reload &>/dev/null || true
    fi
    rm -f "$unit" "$initf" "$LOCAL_SUB_PY"
}

local_sub_selfcheck() {
    local port="$1" token="$2" attempt hit=0
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if curl -fsS --max-time 2 "http://127.0.0.1:${port}/${token}/sub" -o /dev/null 2>/dev/null; then
            hit=1
            break
        fi
        [[ "$attempt" -lt 10 ]] && sleep 0.5
    done
    if [[ "$hit" == "1" ]]; then
        echo "订阅服务自检通过"
    else
        echo "服务已启动，但本机自检未通过（可能仍在启动中）。若持续失败请查看: journalctl -u $LOCAL_SUB_SERVICE -n 50"
    fi
}

install_local_sub_server() {
    if ! command -v python3 &>/dev/null; then
        info "未检测到 python3，尝试自动安装..."
        if command -v apk &>/dev/null; then apk add --no-cache python3
        elif command -v apt-get &>/dev/null; then apt-get update -qq && apt-get install -y -qq python3
        elif command -v yum &>/dev/null; then yum install -y python3
        else die "缺少 python3 且未识别包管理器，请手动安装 python3"; fi
        command -v python3 &>/dev/null || die "python3 自动安装失败，请手动安装后重试"
    fi
    local pybin; pybin=$(command -v python3)

    local state; state=$(load_state 2>/dev/null || true)
    [[ -n "$state" ]] || die "未检测到已部署节点，请先在主菜单执行 [1. 安装节点]"
    ensure_sub_token_present "$state"
    state=$(load_state)

    mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
    local tmp src; tmp=$(mktemp)
    curl -fsSL --max-time 20 "${SCRIPT_RAW_URL%/*}/local_sub_server.py" -o "$tmp" 2>/dev/null || true
    [[ -s "$tmp" ]] || { src="${BASH_SOURCE[0]:-}"; cp "${src%/*}/local_sub_server.py" "$tmp" 2>/dev/null || true; }
    [[ -s "$tmp" ]] && head -n1 "$tmp" | grep -q python3 || { rm -f "$tmp"; die "local_sub_server.py 获取或校验失败"; }
    cp "$tmp" "$LOCAL_SUB_PY" && chmod 700 "$LOCAL_SUB_PY"; rm -f "$tmp"

    local port; port=$(echo "$state" | jq -r '.sub_serve_port // 18080' | tr -d '\r')
    [[ "$port" =~ ^[0-9]+$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 )) || port=18080
    local_sub_stop_unit
    local_sub_kill_strays
    sleep 0.5
    while _port_in_use "$port"; do
        info "端口 $port 已被占用"
        local np=""; read -rp "请输入新端口 (1-65535): " np || die "已取消"
        [[ "$np" =~ ^[0-9]+$ ]] && (( 10#$np >= 1 && 10#$np <= 65535 )) || { info "无效端口: $np"; continue; }
        port=$((10#$np))
    done
    state=$(echo "$state" | jq --argjson p "$port" '.sub_serve_port = $p'); save_state "$state"

    local unit="$SYSTEMD_DIR/$LOCAL_SUB_SERVICE.service" initf="$INITD_DIR/$LOCAL_SUB_SERVICE"
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        mkdir -p "$SYSTEMD_DIR"
        cat > "$unit" <<EOF
[Unit]
Description=xray-cf-lite local subscription server
After=network.target
[Service]
ExecStart=$pybin $LOCAL_SUB_PY --port $port --state $STATE_PATH
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
        [[ "$SKIP_SERVICE" == "1" ]] || { systemctl daemon-reload; systemctl enable --now "$LOCAL_SUB_SERVICE"; }
    else
        mkdir -p "$INITD_DIR"
        cat > "$initf" <<EOF
#!/sbin/openrc-run
name="$LOCAL_SUB_SERVICE"
command="$pybin"
command_args="$LOCAL_SUB_PY --port $port --state $STATE_PATH"
supervisor="supervise-daemon"
respawn_delay=2
respawn_max=0
EOF
        chmod +x "$initf"
        [[ "$SKIP_SERVICE" == "1" ]] || { rc-update add "$LOCAL_SUB_SERVICE" default; rc-service "$LOCAL_SUB_SERVICE" start; }
    fi

    local token; token=$(echo "$state" | jq -r '.sub_token // ""' | tr -d '\r')
    if [[ "$SKIP_SERVICE" != "1" ]]; then
        if ! local_sub_wait_listen "$port"; then
            echo "服务已启动但未在端口 $port 监听，请检查: journalctl -u $LOCAL_SUB_SERVICE -n 50"
            return 0
        fi
        local_sub_selfcheck "$port" "$token"
    fi
    local pub="${XRAY_CF_LITE_PUBLIC_IP:-}"; [[ -n "$pub" ]] || pub=$(get_public_ip 2>/dev/null || true)
    [[ -n "$pub" ]] || pub="<服务器公网IP>"
    local local_sub_url="http://${pub}:${port}/${token}/sub"
    state=$(echo "$state" | jq --arg u "$local_sub_url" '.local_sub_url = $u')
    save_state "$state"
    echo "订阅服务已启动"
    echo "订阅地址: $local_sub_url"
    info "若客户端连不上，请确认云安全组与本机防火墙已放行该端口"
}

change_local_sub_port() {
    local state; state=$(load_state 2>/dev/null || true)
    local unit="$SYSTEMD_DIR/$LOCAL_SUB_SERVICE.service" initf="$INITD_DIR/$LOCAL_SUB_SERVICE"
    local cur_url=""
    [[ -n "$state" ]] && cur_url=$(echo "$state" | jq -r '.local_sub_url // ""' | tr -d '\r')
    if [[ -z "$state" || -z "$cur_url" || ( ! -f "$unit" && ! -f "$initf" ) ]]; then
        info "请先执行 6 安装直连订阅服务"
        return 0
    fi

    local cur_port; cur_port=$(echo "$state" | jq -r '.sub_serve_port // 18080' | tr -d '\r')
    [[ "$cur_port" =~ ^[0-9]+$ ]] && (( 10#$cur_port >= 1 && 10#$cur_port <= 65535 )) || cur_port=18080
    echo "当前直连订阅端口: $cur_port"

    local np="" new_port=""
    while true; do
        read -rp "请输入新端口 (1-65535): " np || { info "已取消"; return 0; }
        if [[ "$np" =~ ^[0-9]+$ ]] && (( 10#$np >= 1 && 10#$np <= 65535 )); then
            new_port=$((10#$np))
            break
        fi
        info "无效端口: $np"
    done

    local_sub_stop_unit
    local_sub_kill_strays
    sleep 0.5
    if _port_in_use "$new_port"; then
        info "端口 $new_port 已被占用，已中止（配置未修改）"
        local_sub_start_unit
        return 0
    fi

    state=$(echo "$state" | jq --argjson p "$new_port" '.sub_serve_port = $p'); save_state "$state"

    local pybin; pybin=$(command -v python3)
    [[ -n "$pybin" ]] || die "缺少 python3，请先安装后重试"
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        mkdir -p "$SYSTEMD_DIR"
        cat > "$unit" <<EOF
[Unit]
Description=xray-cf-lite local subscription server
After=network.target
[Service]
ExecStart=$pybin $LOCAL_SUB_PY --port $new_port --state $STATE_PATH
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
        [[ "$SKIP_SERVICE" == "1" ]] || { systemctl daemon-reload; systemctl restart "$LOCAL_SUB_SERVICE"; }
    else
        mkdir -p "$INITD_DIR"
        cat > "$initf" <<EOF
#!/sbin/openrc-run
name="$LOCAL_SUB_SERVICE"
command="$pybin"
command_args="$LOCAL_SUB_PY --port $new_port --state $STATE_PATH"
supervisor="supervise-daemon"
respawn_delay=2
respawn_max=0
EOF
        chmod +x "$initf"
        [[ "$SKIP_SERVICE" == "1" ]] || rc-service "$LOCAL_SUB_SERVICE" restart
    fi

    local token; token=$(echo "$state" | jq -r '.sub_token // ""' | tr -d '\r')
    local pub="${XRAY_CF_LITE_PUBLIC_IP:-}"; [[ -n "$pub" ]] || pub=$(get_public_ip 2>/dev/null || true)
    [[ -n "$pub" ]] || pub="<服务器公网IP>"
    local local_sub_url="http://${pub}:${new_port}/${token}/sub"
    state=$(echo "$state" | jq --arg u "$local_sub_url" '.local_sub_url = $u'); save_state "$state"
    echo "端口已更新为: $new_port"
    echo "订阅地址: $local_sub_url"
    [[ "$SKIP_SERVICE" == "1" ]] || local_sub_selfcheck "$new_port" "$token"
    info "若客户端连不上，请确认云安全组与本机防火墙已放行该端口"
}

do_sub_manage() {
    while true; do
        local state=""
        state=$(load_state 2>/dev/null || true)
        local sub_base sub_token ip_urls_json ip_count port_mode port_label
        sub_base=$(state_get_sub_base "$state")
        sub_token=$(state_get_sub_token "$state")
        ip_urls_json=$(state_get_ip_urls_json "$state")
        ip_count=$(echo "$ip_urls_json" | jq 'length' | tr -d '\r')
        port_mode=$(state_get_port_mode "$state")
        [[ "$port_mode" == "only_443" ]] && port_label="仅保留 443 端口" || port_label="全部 CF TLS 端口 (443/2053/2083/2087/2096/8443)"

        echo
        echo "── 订阅与优选 IP 管理 (免 CF Key) ──────────────"
        echo "  远程订阅服务: $sub_base${sub_token:+ (已设置密钥)}"
        local sub_port sub_tok
        sub_port=$(echo "$state" | jq -r '.sub_serve_port // 18080' 2>/dev/null | tr -d '\r')
        [[ "$sub_port" =~ ^[0-9]+$ ]] || sub_port=18080
        sub_tok=$(echo "$state" | jq -r '.sub_token // ""' 2>/dev/null | tr -d '\r' || true)
        if local_sub_server_active; then
            local sub_ip="${XRAY_CF_LITE_PUBLIC_IP:-$(get_public_ip 2>/dev/null || true)}"
            echo "  直连订阅:     http://${sub_ip:-<公网IP>}:${sub_port}/${sub_tok}/sub"
        else
            echo "  直连订阅:     未启用（选 6 安装）"
        fi
        echo "  优选 IP 源:   ${ip_count} 个"
        echo "  端口策略:     $port_label"
        if [[ -n "$state" && -f "$LOCAL_SUB_DIR/sub_all_base64.txt" ]]; then
            local lcnt ltime
            lcnt=$(echo "$state" | jq -r '.local_sub_count // 0' | tr -d '\r')
            ltime=$(echo "$state" | jq -r '.local_sub_updated_at // "未知"' | tr -d '\r')
            echo "  本地订阅:     ${lcnt} 个优选地址 (更新于 ${ltime})"
        fi
        echo
        echo "  1. 立即拉取优选 IP 并导出节点文件"
        echo "  2. 管理优选 IP 列表链接"
        echo "  3. 切换优选端口过滤策略"
        echo "  4. 更换远程订阅服务 URL 与密钥"
        echo "  5. 固化/更新快捷命令 x"
        echo "  6. 安装/更新直连订阅服务"
        echo "  7. 更换直连订阅端口"
        echo "  0. 返回主菜单"
        echo

        local sub_choice=""
        read -rp "请选择 [0-7]: " sub_choice || break
        case "$sub_choice" in
            1)
                if [[ -z "$state" ]]; then
                    info "未检测到已部署节点，请先在主菜单执行 [1. 安装节点]"
                    continue
                fi
                generate_local_subscriptions
                ;;
            2)
                if [[ -z "$state" ]]; then
                    info "未检测到已部署节点，请先在主菜单执行 [1. 安装节点]"
                    continue
                fi
                echo
                echo "当前优选 IP 列表链接:"
                echo "$ip_urls_json" | jq -r 'to_entries[] | "  \(.key + 1). \(.value)"'
                echo
                local act=""
                read -rp "操作 (a=添加, d=删除, r=恢复默认4个源, 0=返回): " act || continue
                case "${act,,}" in
                    a)
                        local raw_input=""
                        read -rp "输入优选源 URL (支持空格或逗号分隔多个): " raw_input || continue
                        raw_input="${raw_input//,/ }"
                        local add_arr=() u added=0 updated_urls="$ip_urls_json"
                        read -ra add_arr <<< "$raw_input"
                        for u in "${add_arr[@]}"; do
                            [[ -n "$u" ]] || continue
                            if ! is_safe_url "$u"; then
                                info "跳过无效或不安全的 URL: $u"
                                continue
                            fi
                            if echo "$updated_urls" | jq -e --arg u "$u" 'index($u) != null' &>/dev/null; then
                                info "已存在，跳过: $u"
                                continue
                            fi
                            updated_urls=$(echo "$updated_urls" | jq -c --arg u "$u" '. + [$u]')
                            added=$((added + 1))
                        done
                        if [[ $added -gt 0 ]]; then
                            local new_state
                            new_state=$(echo "$state" | jq --argjson ipu "$updated_urls" '.ip_urls = $ipu')
                            save_state "$(ensure_state_sub_fields "$new_state")"
                            ok "已添加 $added 个优选源"
                            refresh_links_after_sub_change "$(load_state 2>/dev/null || true)"
                        else
                            info "未添加任何有效 URL"
                        fi
                        ;;
                    d)
                        local del_idx=""
                        read -rp "输入要删除的序号 [1-$ip_count]: " del_idx || continue
                        if [[ ! "$del_idx" =~ ^[0-9]+$ ]] || (( del_idx < 1 || del_idx > ip_count )); then
                            info "无效序号: $del_idx"
                            continue
                        fi
                        if (( ip_count <= 1 )); then
                            info "至少保留 1 个优选源（或使用 r 恢复默认）"
                            continue
                        fi
                        local updated_urls new_state
                        updated_urls=$(echo "$ip_urls_json" | jq -c --argjson idx "$((del_idx - 1))" 'del(.[$idx])')
                        new_state=$(echo "$state" | jq --argjson ipu "$updated_urls" '.ip_urls = $ipu')
                        save_state "$(ensure_state_sub_fields "$new_state")"
                        ok "已删除第 $del_idx 个优选源"
                        refresh_links_after_sub_change "$(load_state 2>/dev/null || true)"
                        ;;
                    r)
                        local def_urls new_state
                        def_urls=$(default_ip_urls_json)
                        new_state=$(echo "$state" | jq --argjson ipu "$def_urls" '.ip_urls = $ipu')
                        save_state "$(ensure_state_sub_fields "$new_state")"
                        ok "已恢复默认 4 个优选源"
                        refresh_links_after_sub_change "$(load_state 2>/dev/null || true)"
                        ;;
                    0|"") ;;
                    *) info "未知操作: $act" ;;
                esac
                ;;
            3)
                if [[ -z "$state" ]]; then
                    info "未检测到已部署节点，请先在主菜单执行 [1. 安装节点]"
                    continue
                fi
                echo
                echo "当前策略: $port_label ($port_mode)"
                echo "  1. 全部 CF TLS 端口 (443/2053/2083/2087/2096/8443)"
                echo "  2. 仅保留 443 端口"
                echo "  0. 取消"
                local pm_choice="" new_pm=""
                read -rp "请选择 [0-2]: " pm_choice || continue
                case "$pm_choice" in
                    1) new_pm="all_tls" ;;
                    2) new_pm="only_443" ;;
                    0|"") continue ;;
                    *) info "无效选项: $pm_choice"; continue ;;
                esac
                local new_state
                new_state=$(echo "$state" | jq --arg pm "$new_pm" '.port_mode = $pm')
                save_state "$(ensure_state_sub_fields "$new_state")"
                ok "端口过滤策略已切换为: $new_pm"
                refresh_links_after_sub_change "$(load_state 2>/dev/null || true)"
                ;;
            4)
                if [[ -z "$state" ]]; then
                    info "未检测到已部署节点，请先在主菜单执行 [1. 安装节点]"
                    continue
                fi
                echo
                echo "当前远程订阅服务: $sub_base"
                if [[ -n "$sub_token" ]]; then
                    echo "当前访问密钥:     已设置"
                else
                    echo "当前访问密钥:     (未设置)"
                fi
                local raw_base="" new_base="$sub_base"
                read -rp "新的订阅服务 URL (留空=保持当前, 输入 default=恢复默认): " raw_base || continue
                if [[ -n "$raw_base" ]]; then
                    if [[ "${raw_base,,}" == "default" ]]; then
                        new_base="$DEFAULT_SUB_BASE"
                    else
                        while [[ "$raw_base" == */ ]]; do
                            raw_base="${raw_base%/}"
                        done
                        if [[ ! "$raw_base" =~ ^https?://[^[:space:]]+$ ]]; then
                            info "无效的 URL（需以 http:// 或 https:// 开头）: $raw_base"
                            continue
                        fi
                        new_base="$raw_base"
                    fi
                fi
                local raw_token="" new_token="$sub_token" auto_token="false"
                read -rp "访问密钥 token (输入 auto=自动生成, 回车=保持当前, -=清空): " raw_token || continue
                if [[ "$raw_token" == "-" ]]; then
                    new_token=""
                elif [[ "$raw_token" == "auto" ]]; then
                    new_token=$(gen_uuid | tr -d '-')
                    auto_token="true"
                elif [[ -n "$raw_token" ]]; then
                    new_token="$raw_token"
                fi

                local domain uid routes_json links_json new_state
                domain=$(echo "$state" | jq -r '.domain' | tr -d '\r')
                uid=$(echo "$state" | jq -r '.uuid' | tr -d '\r')
                routes_json=$(echo "$state" | jq -c '.routes' | tr -d '\r')
                links_json=$(gen_all_links "$uid" "$domain" "$routes_json" "$new_base" "$new_token")
                save_links_snapshot "$domain" "$uid" "$links_json"
                new_state=$(echo "$state" | jq \
                    --arg sb "$new_base" --arg st "$new_token" --argjson l "$links_json" \
                    '.sub_base = $sb | .sub_token = $st | .links = $l')
                save_state "$(ensure_state_sub_fields "$new_state")"
                local sync_state sync_old_url sync_port synced_local_url=""
                sync_state=$(load_state 2>/dev/null || true)
                sync_old_url=$(echo "$sync_state" | jq -r '.local_sub_url // ""' | tr -d '\r')
                sync_port=$(echo "$sync_state" | jq -r '.sub_serve_port // ""' | tr -d '\r')
                if [[ -n "$sync_old_url" && -n "$sync_port" ]]; then
                    local sync_pub="${XRAY_CF_LITE_PUBLIC_IP:-}"
                    [[ -n "$sync_pub" ]] || sync_pub=$(get_public_ip 2>/dev/null || true)
                    [[ -n "$sync_pub" ]] || sync_pub="<服务器公网IP>"
                    local sync_new_url="http://${sync_pub}:${sync_port}/${new_token}/sub"
                    if [[ "$sync_new_url" != "$sync_old_url" ]]; then
                        save_state "$(echo "$sync_state" | jq --arg u "$sync_new_url" '.local_sub_url = $u')"
                        synced_local_url="$sync_new_url"
                        [[ -n "$new_token" ]] || info "密钥已清空，直连订阅将拒绝所有请求"
                    fi
                fi
                if [[ "$auto_token" == "true" ]]; then
                    ok "已自动生成访问密钥: $new_token"
                    info "把这串填进 Cloudflare Worker 的 TOKEN 环境变量"
                fi
                ok "远程订阅服务已更新并刷新快照 (未调用 CF API)"
                [[ -n "$synced_local_url" ]] && ok "直连订阅地址已同步: $synced_local_url"
                print_links "$links_json"
                ;;
            5)
                echo
                if [[ -f "$SHORTCUT_PATH" ]]; then
                    echo "当前快捷命令 ($SHORTCUT_PATH):"
                    sed 's/^/  /' "$SHORTCUT_PATH"
                    echo
                fi
                echo "  1. 指向当前 Fork 仓库远程地址 ($SCRIPT_RAW_URL)"
                echo "  2. 固化为本地离线脚本 ($LOCAL_SCRIPT_PATH)"
                echo "  3. 自定义其他远程脚本 Raw URL"
                echo "  0. 返回"
                local sc_choice=""
                read -rp "请选择 [0-3]: " sc_choice || continue
                case "$sc_choice" in
                    1) write_shortcut_remote "$SCRIPT_RAW_URL" ;;
                    2) write_shortcut_local ;;
                    3)
                        local custom_url=""
                        read -rp "输入自定义脚本 Raw URL: " custom_url || continue
                        if ! is_safe_url "$custom_url"; then
                            info "无效或不安全的 URL: $custom_url"
                            continue
                        fi
                        write_shortcut_remote "$custom_url"
                        ;;
                    0|"") ;;
                    *) info "无效选项: $sc_choice" ;;
                esac
                ;;
            6)
                install_local_sub_server
                ;;
            7)
                change_local_sub_port
                ;;
            0)
                return 0
                ;;
            *)
                info "无效选项: $sub_choice"
                ;;
        esac
    done
}

# ── 主入口 ────────────────────────────────────────────
ensure_shortcut() {
    local target="$SHORTCUT_PATH"
    mkdir -p "$(dirname "$target")"
    if ! is_safe_url "$SCRIPT_RAW_URL"; then
        info "忽略不安全的 SCRIPT_RAW_URL，未更新快捷命令: $SCRIPT_RAW_URL"
        return 0
    fi
    local qurl
    qurl=$(printf '%q' "$SCRIPT_RAW_URL")
    if [[ -f "$target" ]]; then
        if grep -q "byJoey/xray-cf-lite" "$target" 2>/dev/null; then
            {
                printf '#!/bin/bash\n'
                printf 'exec bash <(curl -fsSL %s) "$@"\n' "$qurl"
            } > "$target"
            chmod +x "$target"
            info "已将快捷命令 x 自动迁移至当前仓库源"
        fi
        return
    fi
    {
        printf '#!/bin/bash\n'
        printf 'exec bash <(curl -fsSL %s) "$@"\n' "$qurl"
    } > "$target"
    chmod +x "$target"
}

main() {
    [[ "$(id -u)" == "0" ]] || die "请使用 root 运行此脚本"
    detect_init
    install_deps
    need_cmd curl; need_cmd jq
    ensure_shortcut

    local state current_domain="" net_mode=""
    state=$(load_state 2>/dev/null || true)
    if [[ -n "$state" ]]; then
        current_domain=$(echo "$state" | jq -r '.domain // ""')
        net_mode=$(echo "$state" | jq -r '.net_mode // ""')
        ensure_sub_token_present "$state"
    fi

    local ip_count port_mode port_label
    ip_count=$(state_get_ip_urls_json "$state" | jq 'length' | tr -d '\r')
    port_mode=$(state_get_port_mode "$state")
    [[ "$port_mode" == "only_443" ]] && port_label="仅443" || port_label="全部TLS端口"

    echo
    echo "  xray-cf-lite ($INIT_SYSTEM)"
    if [[ -n "$current_domain" ]]; then
        echo "  当前: $current_domain${net_mode:+ [$net_mode]} | 优选源: ${ip_count}个 | 端口策略: $port_label"
    else
        echo "  优选源: ${ip_count}个 | 端口策略: $port_label"
    fi
    echo
    echo "  1. 安装节点"
    echo "  2. 卸载"
    echo "  3. 查看订阅"
    echo "  4. 修改配置(UUID/端口/路径)"
    echo "  5. 查看当前配置"
    echo "  6. 更新外部端口(NAT换端口)"
    echo "  7. 重启 xray"
    echo "  8. 切换网络模式(直连/NAT)"
    echo "  9. 订阅与优选 IP 管理(免CF Key)"
    echo "  0. 退出"
    echo

    read -rp "请选择 [0-9]: " choice
    case "$choice" in
        1) do_install ;; 2) do_uninstall ;; 3) do_show ;;
        4) do_modify ;; 5) do_show_config ;; 6) do_update_ports ;;
        7) do_restart ;; 8) do_switch_net_mode ;; 9) do_sub_manage ;;
        0) exit 0 ;;
        *) die "无效选项: $choice" ;;
    esac
}

if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
    main "$@"
fi
