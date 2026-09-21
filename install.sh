#!/usr/bin/env bash
set -Eeuo pipefail

DEFAULT_PORT="10087"
DEFAULT_BIND="0.0.0.0"
DEFAULT_PREFIX="/opt/waf-panel"
REPO_URL="https://github.com/chrimast/waf-panel.git"
SERVICE_NAME="waf-panel"

PREFIX="$DEFAULT_PREFIX"
PORT=""
BIND="$DEFAULT_BIND"
PASSWORD=""
ASSUME_YES=0
NO_START=0
SOURCE_DIR=""
TEMP_DIR=""

log() { printf '[waf-panel] %s\n' "$*"; }
fail() { printf '[waf-panel] 错误: %s\n' "$*" >&2; exit 1; }
cleanup() { [[ -z "$TEMP_DIR" ]] || rm -rf "$TEMP_DIR"; }
trap cleanup EXIT

usage() {
    cat <<'EOF'
用法: bash install.sh [选项]

  --prefix DIR       安装目录，默认 /opt/waf-panel
  --port PORT        访问端口；未指定时交互输入，默认 10087
  --bind ADDRESS     监听地址，默认 0.0.0.0
  --password VALUE   登录密码；未指定时保留旧密码或随机生成
  --no-start         安装后不启动服务
  -y, --yes          非交互模式，使用默认端口
  -h, --help         显示帮助
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) [[ $# -ge 2 ]] || fail "--prefix 缺少参数"; PREFIX="$2"; shift 2 ;;
        --port) [[ $# -ge 2 ]] || fail "--port 缺少参数"; PORT="$2"; shift 2 ;;
        --bind) [[ $# -ge 2 ]] || fail "--bind 缺少参数"; BIND="$2"; shift 2 ;;
        --password) [[ $# -ge 2 ]] || fail "--password 缺少参数"; PASSWORD="$2"; shift 2 ;;
        --no-start) NO_START=1; shift ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "未知参数: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || fail "请使用 root 用户运行"

prompt_port() {
    local answer=""
    if [[ $ASSUME_YES -eq 0 && -r /dev/tty ]]; then
        printf '请输入访问端口 [默认 %s]: ' "$DEFAULT_PORT" > /dev/tty
        read -r answer < /dev/tty || true
    fi
    PORT="${answer:-$DEFAULT_PORT}"
}

[[ -n "$PORT" ]] || prompt_port
[[ "$PORT" =~ ^[0-9]+$ ]] || fail "端口必须是数字"
(( PORT >= 1 && PORT <= 65535 )) || fail "端口必须在 1-65535 之间"
[[ "$BIND" != *$'\n'* && "$BIND" != *$'\r'* ]] || fail "监听地址格式无效"

command -v docker >/dev/null 2>&1 || fail "未找到 Docker，请先完成 1Panel 安装"
docker info >/dev/null 2>&1 || fail "Docker 未运行"
if ! command -v 1panel >/dev/null 2>&1 && [[ ! -x /usr/local/bin/1panel-core ]]; then
    fail "未检测到 1Panel，请先安装官方 1Panel"
fi
command -v systemctl >/dev/null 2>&1 || fail "当前系统不支持 systemd"

find_waf_base() {
    local candidate
    candidate="/opt/1panel/apps/openresty/openresty/1pwaf/data"
    if [[ -d "$candidate/conf" && -d "$candidate/db/waf" ]]; then
        printf '%s\n' "$candidate"
        return 0
    fi
    for candidate in /opt/1panel/apps/*/*/1pwaf/data; do
        if [[ -d "$candidate/conf" && -d "$candidate/db/waf" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

find_openresty_container() {
    local name
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        if [[ "$name" == 1Panel-openresty* ]]; then
            printf '%s\n' "$name"
            return 0
        fi
    done < <(docker ps --format '{{.Names}}')
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        if docker inspect "$name" --format '{{.Config.Image}}' 2>/dev/null | grep -q '^1panel/openresty:'; then
            printf '%s\n' "$name"
            return 0
        fi
    done < <(docker ps --format '{{.Names}}')
    return 1
}

WAF_BASE="$(find_waf_base)" || fail "未找到 1pwaf 数据目录，请先在 1Panel 安装并启动 OpenResty"
OR_CONTAINER="$(find_openresty_container)" || fail "未找到运行中的 1Panel OpenResty 容器"
docker exec "$OR_CONTAINER" /usr/local/openresty/nginx/sbin/nginx -t >/dev/null 2>&1 \
    || fail "OpenResty 配置检测失败"

ensure_packages() {
    local missing=()
    command -v git >/dev/null 2>&1 || missing+=(git)
    command -v curl >/dev/null 2>&1 || missing+=(curl)
    if ! command -v python3 >/dev/null 2>&1; then
        missing+=(python3 python3-venv)
    elif ! python3 -m venv --help >/dev/null 2>&1; then
        missing+=(python3-venv)
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        command -v apt-get >/dev/null 2>&1 || fail "缺少依赖: ${missing[*]}；当前仅支持 apt 系统自动安装"
        log "安装系统依赖: ${missing[*]}"
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates python3-pip "${missing[@]}"
    fi
}
ensure_packages

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
if [[ -f "$SCRIPT_DIR/main.py" && -f "$SCRIPT_DIR/requirements.txt" ]]; then
    SOURCE_DIR="$SCRIPT_DIR"
else
    TEMP_DIR="$(mktemp -d)"
    log "下载项目源码"
    git clone --depth 1 "$REPO_URL" "$TEMP_DIR/source"
    SOURCE_DIR="$TEMP_DIR/source"
fi

[[ -f "$SOURCE_DIR/main.py" && -f "$SOURCE_DIR/config.py" ]] || fail "项目源码不完整"
mkdir -p "$PREFIX" "$PREFIX/templates" "$PREFIX/static" "$PREFIX/scripts" "$PREFIX/generated" "$PREFIX/backups"

copy_file() {
    local source="$1" target="$2" mode="${3:-0644}"
    if [[ "$(readlink -f "$source")" == "$(readlink -m "$target")" ]]; then
        chmod "$mode" "$target"
        return
    fi
    install -m "$mode" "$source" "$target"
}

for file in main.py config.py autoban.py requirements.txt; do
    copy_file "$SOURCE_DIR/$file" "$PREFIX/$file"
done
copy_file "$SOURCE_DIR/install.sh" "$PREFIX/install.sh" 0755
if [[ "$(readlink -f "$SOURCE_DIR")" != "$(readlink -f "$PREFIX")" ]]; then
    cp -a "$SOURCE_DIR/templates/." "$PREFIX/templates/"
    cp -a "$SOURCE_DIR/static/." "$PREFIX/static/"
    if [[ -d "$SOURCE_DIR/scripts" ]]; then
        cp -a "$SOURCE_DIR/scripts/." "$PREFIX/scripts/"
    fi
fi

if [[ ! -x "$PREFIX/venv/bin/python" ]]; then
    log "创建独立 Python 环境"
    python3 -m venv "$PREFIX/venv"
fi
"$PREFIX/venv/bin/python" -m pip install --upgrade pip
"$PREFIX/venv/bin/python" -m pip install -r "$PREFIX/requirements.txt"

ENV_FILE="$PREFIX/.env"
OLD_PASSWORD=""
if [[ -f "$ENV_FILE" ]]; then
    OLD_PASSWORD="$(python3 - "$ENV_FILE" <<'PY'
import pathlib, shlex, sys
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if line.startswith("WAF_PANEL_PASSWORD="):
        try:
            print(shlex.split(line, posix=True)[0].split("=", 1)[1])
        except (IndexError, ValueError):
            pass
        break
PY
)"
fi
if [[ -z "$PASSWORD" ]]; then
    PASSWORD="$OLD_PASSWORD"
fi
if [[ -z "$PASSWORD" ]]; then
    PASSWORD="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(18))
PY
)"
    GENERATED_PASSWORD=1
else
    GENERATED_PASSWORD=0
fi
[[ "$PASSWORD" != *$'\n'* && "$PASSWORD" != *$'\r'* ]] || fail "密码不能包含换行"

write_env_value() {
    local key="$1" value="$2"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '%s="%s"\n' "$key" "$value"
}
{
    write_env_value WAF_PANEL_HOME "$PREFIX"
    write_env_value WAF_BASE "$WAF_BASE"
    write_env_value OR_CONTAINER "$OR_CONTAINER"
    write_env_value WAF_PANEL_PASSWORD "$PASSWORD"
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=1Panel WAF Management Panel
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
WorkingDirectory=$PREFIX
EnvironmentFile=$ENV_FILE
ExecStart=$PREFIX/venv/bin/python -m uvicorn main:app --host $BIND --port $PORT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null
if [[ $NO_START -eq 0 ]]; then
    systemctl restart "$SERVICE_NAME"
    for _ in {1..20}; do
        if systemctl is-active --quiet "$SERVICE_NAME" && \
           curl -fsS "http://127.0.0.1:$PORT/login" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    systemctl is-active --quiet "$SERVICE_NAME" || {
        journalctl -u "$SERVICE_NAME" -n 30 --no-pager >&2 || true
        fail "服务启动失败"
    }
    curl -fsS "http://127.0.0.1:$PORT/login" >/dev/null 2>&1 || {
        journalctl -u "$SERVICE_NAME" -n 30 --no-pager >&2 || true
        fail "服务健康检查失败"
    }
fi

HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
HOST_IP="${HOST_IP:-127.0.0.1}"
log "安装完成"
printf '访问地址: http://%s:%s\n' "$HOST_IP" "$PORT"
printf '安装目录: %s\n' "$PREFIX"
printf 'WAF 数据: %s\n' "$WAF_BASE"
printf 'OpenResty 容器: %s\n' "$OR_CONTAINER"
if [[ $GENERATED_PASSWORD -eq 1 ]]; then
    printf '登录密码: %s\n' "$PASSWORD"
else
    printf '登录密码: 已保留或使用指定密码\n'
fi
printf '\n接下来: 浏览器打开上面的地址 → 仪表盘看 WAF 是否运行 → 自动封禁点「开启保护」。\n'
