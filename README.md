# waf-panel

给已经装好 1Panel + OpenResty 的服务器用的 **WAF Agent**。本仓库不再提供总控网页；总控在 [CF-Monitor](https://github.com/chrimast/CF-Monitor) 后台。

不改 1Panel 程序。自动封禁默认用宿主机 `INPUT` 链 + `iptables-allports`，把攻击者整机封死在 OpenResty 前面；只写：

```text
/etc/fail2ban/jail.d/waf-panel-autoban.local
```

## 安装 Agent

在 1Panel 机器上用 root 执行：

```bash
curl -fsSL https://raw.githubusercontent.com/chrimast/waf-panel/main/install.sh | sudo bash -s -- --role agent -y
```

脚本会自动找 1pwaf 目录和 OpenResty 容器，装到 `/opt/waf-panel`，端口默认 `10087`。终端会打印：

- 运行角色：`agent`
- Agent 地址：`http://公网IP:10087`
- Agent Token

指定端口和 Token：

```bash
curl -fsSL https://raw.githubusercontent.com/chrimast/waf-panel/main/install.sh | bash -s -- --role agent --port 10087 --agent-token '你的Token' -y
```

查看本机 Token（不要把引号一起复制）：

```bash
grep WAF_AGENT_TOKEN /opt/waf-panel/.env
```

到 CF-Monitor 后台打开 **WAF**：

1. 填名称
2. Agent 地址填公网 `http://公网IP:10087`
3. 填 Token（不要带引号）
4. 点添加，再打开仪表盘 / 攻击日志 / 封禁 / 自动封禁

单独安装：

```bash
curl -fsSL https://raw.githubusercontent.com/chrimast/waf-panel/main/install.sh | sudo bash -s -- --role agent -y
```

安全卸载（保留 Token 和配置）：

```bash
curl -fsSL https://raw.githubusercontent.com/chrimast/waf-panel/main/uninstall.sh | sudo bash -s -- -y
```

仅确认要删除整个 `/opt/waf-panel`（含 Token、备份）时，才添加 `--purge-data`。

Agent 需要能被 Cloudflare Worker 访问。请填公网 `http://公网IP:10087`，不要填 localhost 或内网地址。封禁按节点执行，A 机封的 IP 不会自动出现在 B 机。

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

把 `.env.docker` 里的 `OR_CONTAINER` 改成实际名称，并填写 `WAF_AGENT_TOKEN`。角色固定为 `agent`。

然后：

```bash
docker compose up -d --build
```

## License
