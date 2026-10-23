#!/usr/bin/env bash
set -Eeuo pipefail

PREFIX="/opt/waf-panel"
SERVICE_NAME="waf-panel"
PURGE_DATA=0
ASSUME_YES=0

usage() {
    cat <<'EOF'
用法: bash uninstall.sh [选项]

  --prefix DIR       安装目录，默认 /opt/waf-panel
  --purge-data      同时删除 Agent 安装目录、Token、虚拟环境和备份
  -y, --yes         非交互确认
  -h, --help        显示帮助

默认只删除 systemd 服务，保留安装目录和配置，便于以后重新安装并保留 Token。
不会删除 1Panel、OpenResty、1pwaf 数据或 fail2ban 主配置。
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) [[ $# -ge 2 ]] || { echo "--prefix 缺少参数" >&2; exit 1; }; PREFIX="$2"; shift 2 ;;
        --purge-data) PURGE_DATA=1; shift ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数: $1" >&2; exit 1 ;;
    esac
done

[[ $(id -u) -eq 0 ]] || { echo "请使用 root 用户运行" >&2; exit 1; }
if [[ $PURGE_DATA -eq 1 ]]; then
    [[ -f "$PREFIX/main.py" && -f "$PREFIX/.env" ]] || {
        echo "拒绝清理：目录不是完整的 waf-panel Agent 安装（缺少 main.py 或 .env）" >&2
        exit 1
    }
    grep -Fq "WAF_PANEL_HOME=\"$PREFIX\"" "$PREFIX/.env" || {
        echo "拒绝清理：.env 中的 WAF_PANEL_HOME 与目标目录不一致" >&2
        exit 1
    }
fi

if [[ $ASSUME_YES -eq 0 ]]; then
    if [[ $PURGE_DATA -eq 1 ]]; then
        printf '将删除服务和 %s 全部数据，继续？[y/N] ' "$PREFIX" >/dev/tty
    else
        printf '将删除 waf-panel 服务并保留 %s，继续？[y/N] ' "$PREFIX" >/dev/tty
    fi
    read -r answer </dev/tty || true
    [[ "${answer:-}" =~ ^[Yy]$ ]] || { echo "已取消"; exit 0; }
fi

systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true

if [[ $PURGE_DATA -eq 1 ]]; then
    rm -rf -- "$PREFIX"
    printf '已删除服务和数据目录: %s\n' "$PREFIX"
else
    printf '已删除服务，保留数据目录: %s\n' "$PREFIX"
    printf '如需彻底删除，再执行: sudo bash uninstall.sh --purge-data -y\n'
fi
printf '未修改 1Panel、OpenResty、1pwaf 数据或 fail2ban 主配置。\n'
