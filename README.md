# waf-panel

1Panel OpenResty/1pwaf 的独立 WAF 管理面板。支持原生 systemd 部署，也支持 Docker Compose 部署。

## Docker 部署

Docker 版需要访问宿主机的：

- 1pwaf 数据目录；
- Docker socket，用于 OpenResty reload；
- Fail2ban socket，用于状态、校验、重载和封禁操作。

首次部署：

```bash
cp .env.docker.example .env.docker
# 编辑 .env.docker，至少设置 WAF_PANEL_PASSWORD
chmod 600 .env.docker
docker compose up -d --build
```

默认监听 `10087`。Docker 版使用 `network_mode: host`，访问：

```text
http://服务器IP:10087/login
```

容器不会修改 1Panel 源码、OpenResty 配置或系统 `jail.local`；它只通过挂载的数据目录和 Fail2ban socket 执行已有面板范围内的操作。

## 注意

Docker 版必须确保宿主机 Fail2ban 已运行，并且存在 `/var/run/fail2ban/fail2ban.sock`。如果宿主机的 OpenResty 容器名或 1pwaf 路径不同，修改 `.env.docker` 中的 `WAF_BASE` 和 `OR_CONTAINER`。

## 原生部署

原有 `install.sh` 和 `waf-panel.service` 仍可使用。
