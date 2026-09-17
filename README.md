# waf-panel

1Panel OpenResty / 1pwaf 的独立 WAF 管理面板。可用 Docker Compose 或原生 systemd 部署。

面板只读写 1pwaf 数据文件和独立的 Fail2ban 配置，不修改 1Panel 源码。自动封禁写入：

```text
/etc/fail2ban/jail.d/waf-panel-autoban.local
```

不会改 1Panel 的 `/etc/fail2ban/jail.local`。

## Docker Compose 部署

适合已经安装 1Panel，并且 OpenResty 正在运行的服务器。

### 1. 获取项目

```bash
git clone https://github.com/chrimast/waf-panel.git
cd waf-panel
```

### 2. 准备环境文件

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

| 变量 | 含义 | 如何填写 |
| --- | --- | --- |
| `WAF_PANEL_PASSWORD` | 打开面板时的登录密码 | 自己设置，不要使用示例值 |
| `WAF_BASE` | 1Panel 的 1pwaf 数据目录 | 默认值适用于常见 1Panel 安装；目录里应能看到 `conf` 和 `db/waf` |
| `OR_CONTAINER` | 1Panel OpenResty 容器名 | 每台服务器可能不同，见下面查询命令 |

查看本机 OpenResty 容器名：

```bash
docker ps --format '{{.Names}}' | grep -i openresty
```

如果查到的名字不是 `1Panel-openresty-bGB2`，把 `.env.docker` 里的 `OR_CONTAINER` 改成实际名称。

### 3. 确认端口

默认访问端口是 `10087`。Compose 使用 `network_mode: host`，所以容器会直接占用宿主机的 `10087`。

如果要改端口，下面三处必须改成同一个数字：

- `Dockerfile` 的 `EXPOSE` 和 `--port`
- `docker-compose.yml` 的 healthcheck 地址
- 访问地址里的端口

一般不需要改端口。

### 4. 启动

```bash
docker compose up -d --build
```

打开：

```text
http://服务器IP:10087/login
```

用 `.env.docker` 里的 `WAF_PANEL_PASSWORD` 登录。

查看状态：

```bash
docker compose ps
docker compose logs -f waf-panel
```

### 5. 会自动挂载哪些目录

Compose 会挂载面板运行所需的宿主机资源：

- 1pwaf 数据目录（`WAF_BASE`）
- Docker socket，用于 reload OpenResty
- Fail2ban socket 和 `/etc/fail2ban`
- OpenResty、站点、系统日志目录
- `waf-panel-data` 数据卷，保存面板自己的运行数据

Docker 版不会修改 1Panel 源码。

## 原生 systemd 部署

适合不使用 Compose、直接在宿主机跑面板的场景。需要 root、Docker、1Panel 和 systemd。

```bash
git clone https://github.com/chrimast/waf-panel.git
cd waf-panel
bash install.sh
```

常用参数：

```bash
bash install.sh --port 10087 --password '你的登录密码'
```

安装脚本会自动查找 1pwaf 数据目录和正在运行的 OpenResty 容器，并把服务安装到 `/opt/waf-panel`。完成后访问：

```text
http://服务器IP:10087/login
```

## License

MIT
