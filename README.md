# waf-panel

给已经装好 1Panel + OpenResty 的服务器用的 WAF 管理面板。可以管本机，也可以把其他 1Panel 服务器当成节点加进来。

不改 1Panel 程序。自动封禁默认用宿主机 `INPUT` 链 + `iptables-allports`，把攻击者整机封死在 OpenResty 前面；只写：

```text
/etc/fail2ban/jail.d/waf-panel-autoban.local
```

## 角色

同一套代码，安装时用 `--role` 区分：

| 角色 | 用途 | 浏览器 |
| --- | --- | --- |
| **console（默认）** | 总控后台。本机默认就是第一台节点 | `http://IP:10087/login` |
| **agent** | 其他 1Panel 机器上的节点接口 | 不提供登录页 |

总控选中远程节点后，仪表盘、攻击日志、封禁、自动封禁、拦截页面都作用在那台机器上。本机不必再装一份 Agent。

## 最快安装（总控）

在总控服务器用 root 执行：

```bash
curl -fsSL https://raw.githubusercontent.com/chrimast/waf-panel/main/install.sh | bash
```

脚本会自动找 1pwaf 目录和 OpenResty 容器，装到 `/opt/waf-panel`，端口默认 `10087`。

装完打开：

```text
http://服务器IP:10087/login
```

终端会打印登录密码和 Agent Token。进去后打开「自动封禁」，点「开启保护」。登录后可在侧栏「总控密码」改掉总控网页的初始密码，改完需要重新登录；这不会改远程 Agent。

指定密码和端口：

```bash
curl -fsSL https://raw.githubusercontent.com/chrimast/waf-panel/main/install.sh | bash -s -- --password '你的密码' --port 10087
```

已有总控升级，在同一台机器再跑一遍上面的安装命令即可。登录密码和 Agent Token 会保留。

查看本机 Token：

```bash
grep WAF_AGENT_TOKEN /opt/waf-panel/.env
```

## 其他服务器装 Agent

在远程 1Panel 机器上：

```bash
curl -fsSL https://raw.githubusercontent.com/chrimast/waf-panel/main/install.sh | bash -s -- --role agent -y
```

终端会打印：

- 运行角色：`agent`
- Agent 地址：`http://那台IP:10087`
- Agent Token

到总控后台打开「节点」：

1. 填名称、Agent 地址、Token
2. 点添加
3. 用侧栏「当前节点」切换本机或远程

Agent 不要对公网裸奔，能被总控访问即可。封禁按节点执行，A 机封的 IP 不会自动出现在 B 机。

指定 Agent 端口和 Token：

```bash
curl -fsSL https://raw.githubusercontent.com/chrimast/waf-panel/main/install.sh | bash -s -- --role agent --port 10087 --agent-token '你的Token' -y
```

## 装好以后做什么

1. 仪表盘：确认当前节点的 WAF 是运行中。
2. 自动封禁：点「开启保护」。默认封本机防火墙并写入 WAF 黑名单。灵敏度可选宽松 / 标准 / 严格。
3. 日志路径不用手填。面板会探测 1Panel v1（`openresty/www/sites`）和 v2（`/opt/1panel/www/sites`）。
4. 用了 Cloudflare 才去「高级设置」里填邮箱和 API。Jail / Filter 也在高级设置。

## Docker Compose

已经熟悉 Compose 时可以用。需要自己填 OpenResty 容器名。

```bash
git clone https://github.com/chrimast/waf-panel.git
cd waf-panel
cp .env.docker.example .env.docker
```

查看容器名：

```bash
docker ps --format '{{.Names}}' | grep -i openresty
```

把 `.env.docker` 里的 `OR_CONTAINER` 改成实际名称。

- 总控：`WAF_PANEL_ROLE=console`
- 只当 Agent：`WAF_PANEL_ROLE=agent`，并填写 `WAF_AGENT_TOKEN`

然后：

```bash
docker compose up -d --build
```

总控访问 `http://服务器IP:10087/login`。

```yaml
services:
  waf-panel:
    build: .
    image: waf-panel:latest
    container_name: waf-panel
    restart: unless-stopped
    network_mode: host
    env_file:
      - .env.docker
    environment:
      WAF_PANEL_HOME: /app
      WAF_BASE: ${WAF_BASE:-/opt/1panel/apps/openresty/openresty/1pwaf/data}
      OR_CONTAINER: ${OR_CONTAINER:-1Panel-openresty-bGB2}
      FAIL2BAN_SOCKET: /var/run/fail2ban/fail2ban.sock
      WAF_PANEL_DOCKER: "1"
      FAIL2BAN_ROOT: /etc/fail2ban
      WAF_PANEL_ROLE: ${WAF_PANEL_ROLE:-console}
      WAF_AGENT_TOKEN: ${WAF_AGENT_TOKEN:-}
    volumes:
      - ${WAF_BASE:-/opt/1panel/apps/openresty/openresty/1pwaf/data}:${WAF_BASE:-/opt/1panel/apps/openresty/openresty/1pwaf/data}:rw
      - /var/run/docker.sock:/var/run/docker.sock
      - /var/run/fail2ban:/var/run/fail2ban
      - /etc/fail2ban:/etc/fail2ban:rw
      - /opt/1panel/apps/openresty/openresty/log:/opt/1panel/apps/openresty/openresty/log:ro
      - /opt/1panel/www/sites:/opt/1panel/www/sites:ro
      - /opt/1panel/apps/openresty/openresty/www/sites:/opt/1panel/apps/openresty/openresty/www/sites:ro
      - /var/log:/var/log:ro
      - waf-panel-data:/app/data
    healthcheck:
      test: ["CMD", "python", "-c", "import socket; s=socket.create_connection(('127.0.0.1',10087),3); s.close()"]
      interval: 30s
      timeout: 5s
      retries: 3
volumes:
  waf-panel-data:
```

## License
