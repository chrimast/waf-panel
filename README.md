# waf-panel

给已经装好 1Panel + OpenResty 的服务器用的 WAF 管理面板。打开浏览器就能看攻击、封 IP、开自动封禁。

不改 1Panel 程序。自动封禁只写：

```text
/etc/fail2ban/jail.d/waf-panel-autoban.local
```

## 最快安装（推荐）

在服务器上用 root 执行：

```bash
curl -fsSL https://raw.githubusercontent.com/chrimast/waf-panel/main/install.sh | bash
```

脚本会自动找 1pwaf 目录和 OpenResty 容器，装到 `/opt/waf-panel`，端口默认 `10087`。

装完打开：

```text
http://服务器IP:10087/login
```

终端里会打印登录密码。进去后打开「自动封禁」，点「开启保护」。日志路径、Jail、Filter 都在「高级设置」里。

指定密码和端口：

```bash
curl -fsSL https://raw.githubusercontent.com/chrimast/waf-panel/main/install.sh | bash -s -- --password '你的密码' --port 10087
```

## 装好以后做什么

1. 仪表盘：确认 WAF 是运行中。
2. 自动封禁：点「开启保护」。默认封本机防火墙并写入 WAF 黑名单。灵敏度可选宽松 / 标准 / 严格。
3. 日志路径不用手填。面板会探测 1Panel v1（`openresty/www/sites`）和 v2（`/opt/1panel/www/sites`），两边都在就都监听。
4. 用了 Cloudflare 才去「高级设置」里填邮箱和 API，日常可以不填。 Jail / Filter 也在高级设置。

## Docker Compose

已经熟悉 Compose 时可以用。需要自己填 OpenResty 容器名：

```bash
git clone https://github.com/chrimast/waf-panel.git
cd waf-panel
cp .env.docker.example .env.docker
```

查看容器名：

```bash
docker ps --format '{{.Names}}' | grep -i openresty
```

把 `.env.docker` 里的 `OR_CONTAINER` 改成实际名称，然后：

```bash
docker compose up -d --build
```

访问 `http://服务器IP:10087/login`。

## License
