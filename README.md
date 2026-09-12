# waf-panel

1Panel OpenResty/1pwaf 的独立 WAF 管理面板，支持原生 systemd 和 Docker Compose 部署。

## Docker Compose 部署

### 1. 获取项目

```bash
git clone https://github.com/chrimast/waf-panel.git
cd waf-panel
```

### 2. 配置环境变量

```bash
cp .env.docker.example .env.docker
chmod 600 .env.docker
```

编辑 `.env.docker`：

```dotenv
WAF_PANEL_PASSWORD=请设置面板登录密码
WAF_BASE=/opt/1panel/apps/openresty/openresty/1pwaf/data
OR_CONTAINER=1Panel-openresty-bGB2
```

配置说明：

- `WAF_PANEL_PASSWORD`：WAF 面板登录密码；
- `WAF_BASE`：1Panel `1pwaf` 数据目录；
- `OR_CONTAINER`：1Panel OpenResty 容器名称。

### 3. 修改 Compose 配置（按需）

默认面板端口为 `10087`。如果 1Panel 的路径或 OpenResty 容器名称不同，修改 `.env.docker` 中的 `WAF_BASE` 和 `OR_CONTAINER`。

如果需要修改端口，编辑 `docker-compose.yml` 和 `Dockerfile` 中的 `10087`，保持两处一致。

### 4. 部署项目

```bash
docker compose up -d --build
```

部署完成后访问：

```text
http://服务器IP:10087/login
```

### 5. 项目运行所需的挂载

Compose 会自动挂载项目运行所需的宿主机资源：

- 1Panel `1pwaf` 数据目录；
- Docker socket，用于 OpenResty reload；
- Fail2ban socket 和配置目录；
- OpenResty、站点和系统日志目录；
- `waf-panel-data` 数据卷，用于保存面板运行数据。

Docker 版不会修改 1Panel 源码；WAF 自动封禁配置只写入独立的面板管理范围。

## 原生 systemd 部署

原有 `install.sh` 和 `waf-panel.service` 仍可用于非 Docker 部署。

## License

MIT
