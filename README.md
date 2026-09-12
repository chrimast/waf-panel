# waf-panel

1Panel OpenResty/1pwaf 的独立 WAF 管理面板。支持原生 systemd 部署，也支持 Docker Compose 部署。

## Docker Compose 部署

Docker 版适用于已经安装并运行 1Panel、OpenResty/1pwaf 和 Fail2ban 的宿主机。面板容器需要访问宿主机的 1pwaf 数据目录、Docker socket、Fail2ban socket 以及相关日志目录，因此请只在可信的管理环境中暴露面板端口。

### 前置条件

- Linux 宿主机；
- Docker Engine；
- Docker Compose v2（命令为 `docker compose`）；
- 1Panel OpenResty/1pwaf 已安装并运行；
- 宿主机 Fail2ban 已安装并运行；
- 存在 `/var/run/docker.sock` 和 `/var/run/fail2ban/fail2ban.sock`；
- 确认 1pwaf 数据目录和 OpenResty 容器名称。

检查依赖：

```bash
docker --version
docker compose version
docker info

test -S /var/run/docker.sock && echo "Docker socket OK"
test -S /var/run/fail2ban/fail2ban.sock && echo "Fail2ban socket OK"
```

### 获取代码

```bash
git clone https://github.com/chrimast/waf-panel.git
cd waf-panel
```

如果已经有代码目录，更新前先查看本地修改：

```bash
git status --short
git pull --ff-only
```

### 配置环境变量

复制 Docker 环境变量模板：

```bash
cp .env.docker.example .env.docker
chmod 600 .env.docker
```

编辑 `.env.docker`：

```dotenv
WAF_PANEL_PASSWORD=请替换为强密码
WAF_BASE=/opt/1panel/apps/openresty/openresty/1pwaf/data
OR_CONTAINER=1Panel-openresty-bGB2
```

说明：

- `WAF_PANEL_PASSWORD`：面板登录密码，必须修改为强密码；
- `WAF_BASE`：宿主机 1pwaf 数据目录；
- `OR_CONTAINER`：运行中的 1Panel OpenResty 容器名称；
- `.env.docker` 含有敏感信息，不要提交到 GitHub。

获取 OpenResty 容器名称：

```bash
docker ps --format '{{.Names}}\t{{.Image}}' | grep -Ei 'openresty|1panel'
```

获取 1pwaf 数据目录：

```bash
find /opt/1panel/apps -type d -path '*/1pwaf/data' -print
```

### 检查 Compose 配置

```bash
docker compose config
```

如果只想检查配置而不启动容器，以上命令不会创建或修改 WAF 运行配置。

### 构建并启动

```bash
docker compose up -d --build
```

默认监听端口为 `10087`，访问：

```text
http://服务器IP:10087/login
```

如果云服务器或宿主机启用了防火墙，只放行可信来源访问 `10087`，不要无条件对公网开放。生产环境建议通过 VPN、SSH 隧道、Cloudflare Access 或带认证的反向代理访问。

### 查看状态和日志

```bash
docker compose ps
docker compose logs --tail=200 -f waf-panel
```

健康检查：

```bash
curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:10087/login
```

容器内检查 Fail2ban socket：

```bash
docker compose exec waf-panel fail2ban-client ping
docker compose exec waf-panel fail2ban-client status
```

### 更新 Docker 版

先备份 `.env.docker` 和宿主机 WAF/Fail2ban 配置，然后执行：

```bash
git pull --ff-only
docker compose up -d --build
docker compose ps
```

不要执行 `docker compose down -v`，否则可能删除 Compose 管理的运行数据卷。普通重建会保留 `waf-panel-data` 数据卷和宿主机 WAF 数据。

### 停止、重启和卸载

```bash
# 重启容器
docker compose restart

# 停止并删除容器，不删除数据卷
docker compose down

# 删除容器及本项目数据卷（确认不再需要后再执行）
docker compose down -v
```

卸载 Docker 版不会自动删除宿主机的 1Panel、OpenResty、Fail2ban 或 WAF 数据。删除宿主机 WAF/Fail2ban 配置前，请先确认其中没有其他服务正在使用。

### Docker 版权限和安全边界

容器挂载了：

- 1pwaf 数据目录（读写）；
- `/var/run/docker.sock`（用于 OpenResty reload）；
- `/var/run/fail2ban` 和 `/etc/fail2ban`（用于 Fail2ban 操作）；
- OpenResty、站点和系统日志目录（只读）。

因此该容器具有较高的宿主机管理权限。不要把它部署到不可信主机，也不要把 `.env.docker`、WAF 配置、备份或日志提交到公共仓库。

Docker 版不会修改 1Panel 源码；它只通过挂载的数据目录和 Fail2ban 接口执行面板范围内的操作。自动封禁配置仍然只写入独立的 `waf-panel-autoban.local` 管理范围，不应覆盖 1Panel 的 SSH Jail 或系统默认设置。

## 原生 systemd 部署

原有 `install.sh` 和 `waf-panel.service` 仍可使用。原生部署不需要 Docker Compose，但需要宿主机具备 Python、systemd、1Panel OpenResty/1pwaf 和 Fail2ban。

## License

MIT
