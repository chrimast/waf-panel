import os
import subprocess
import sys
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]


class ConfigEnvironmentTests(unittest.TestCase):
    def test_config_reads_install_environment(self):
        env = os.environ.copy()
        env.update(
            {
                "WAF_PANEL_HOME": "/srv/waf-panel",
                "WAF_BASE": "/srv/1panel/1pwaf/data",
                "OR_CONTAINER": "1Panel-openresty-test",
                "WAF_PANEL_PASSWORD": "secret-value",
            }
        )
        code = (
            "import config; "
            "print(config.PANEL_HOME); print(config.WAF_BASE); "
            "print(config.OR_CONTAINER); print(config.PANEL_PASSWORD)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=PROJECT_DIR,
            env=env,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "/srv/waf-panel",
                "/srv/1panel/1pwaf/data",
                "1Panel-openresty-test",
                "secret-value",
            ],
        )

    def test_main_uses_configured_panel_home_for_assets(self):
        source = (PROJECT_DIR / "main.py").read_text()
        self.assertIn('StaticFiles(directory=os.path.join(PANEL_HOME, "static"))', source)
        self.assertIn('os.path.join(PANEL_HOME, "templates", "index.html")', source)
        self.assertNotIn('"/opt/waf-panel/static"', source)
        self.assertNotIn('"/opt/waf-panel/templates/index.html"', source)


class InstallerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (PROJECT_DIR / "install.sh").read_text()

    def test_default_port_is_10087_and_prompt_is_interactive(self):
        self.assertIn('DEFAULT_PORT="10087"', self.source)
        self.assertIn("请输入访问端口", self.source)
        self.assertIn("read -r", self.source)

    def test_installer_is_non_invasive_to_1panel(self):
        self.assertNotIn("/etc/fail2ban/jail.local", self.source)
        self.assertNotIn("docker-compose.yml", self.source)
        self.assertNotIn("nginx.conf", self.source)


    def test_docker_contract(self):
        compose = (PROJECT_DIR / "docker-compose.yml").read_text()
        dockerfile = (PROJECT_DIR / "Dockerfile").read_text()
        self.assertIn("/var/run/docker.sock:/var/run/docker.sock", compose)
        self.assertIn("/var/run/fail2ban:/var/run/fail2ban", compose)
        self.assertIn("/etc/fail2ban:/etc/fail2ban:rw", compose)
        self.assertIn("WAF_PANEL_DOCKER", compose)
        self.assertIn("python:3.11-slim", dockerfile)
        source = (PROJECT_DIR / "autoban.py").read_text()
        self.assertIn("FAIL2BAN_ROOT", source)
        self.assertIn("fail2ban-client", source)
        self.assertIn("detect_default_logpaths", source)
        compose = (PROJECT_DIR / "docker-compose.yml").read_text()
        self.assertIn("/opt/1panel/apps/openresty/openresty/www/sites", compose)
        readme = (PROJECT_DIR / "README.md").read_text()
        self.assertIn("curl -fsSL https://raw.githubusercontent.com/chrimast/waf-panel/main/install.sh | bash", readme)
        self.assertNotIn("三步开始", (PROJECT_DIR / "templates/index.html").read_text())
        html = (PROJECT_DIR / "templates/index.html").read_text()
        self.assertIn("input#abEnabled", html)
        self.assertRegex(html, r"input#abEnabled\{[^}]*min-height:0")
        self.assertIn('id="abSimpleView"', html)
        self.assertIn("开启保护", html)
        self.assertIn("关闭保护", html)
        self.assertIn("toggleAutobanProtection", html)
        self.assertIn("applyAutobanPreset('loose')", html)
        self.assertIn("applyAutobanPreset('standard')", html)
        self.assertIn("applyAutobanPreset('strict')", html)
        self.assertIn('id="abAdvanced"', html)
        self.assertLess(html.index('id="abSimpleView"'), html.index('id="abAdvanced"'))
        self.assertLess(html.index('id="abAdvanced"'), html.index(">主 Jail</h3>"))
        self.assertIn("高级设置", html)
        self.assertIn("保护已开启", html)
        self.assertIn("保护未开启", html)
        self.assertIn("灵敏度", html)
        self.assertIn("保存配置（不重启）", html)
        self.assertIn("应用配置并重启", html)
        self.assertIn("封禁管理", html)
        self.assertIn("nav('bans')", html)
        self.assertNotIn("nav('blocks')", html)
        self.assertNotIn("nav('blacklist')", html)
        self.assertIn('data-page="dashboard"', html)
        self.assertIn('data-page="nodes"', html)
        self.assertIn('data-page="password"', html)
        self.assertIn("nav('nodes')", html)
        self.assertIn("nav('password')", html)
        self.assertIn("正在管理", html)
        self.assertIn('id="nodeList"', html)
        self.assertIn("node-item", html)
        self.assertIn("nodeStatusDot", html)
        self.assertIn("node-dot", html)
        self.assertNotIn("nodeStatusBadge(n,true)", html)
        self.assertNotIn("${kind} · ${state}", html)
        self.assertNotIn('id="nodeSelect"', html)
        self.assertNotIn("<select id=\"nodeSelect\"", html)
        self.assertIn("id=\"scopeBar\"", html)
        self.assertIn("本机总控", html)
        self.assertIn("远程 Agent", html)
        self.assertIn("总控登录密码", html)
        self.assertIn("不影响 Agent", html)
        self.assertIn("连接状态", html)
        self.assertIn("nodeStatusBadge", html)
        self.assertIn("refreshNodes()", html)
        self.assertIn("pageFromHash", html)
        self.assertIn("loadNodes().then(()=>nav(pageFromHash()))", html)
        self.assertNotIn("loadNodes().then(()=>nav('dashboard'))", html)
        self.assertIn("password.py", self.source)
        self.assertIn("<h1>封禁管理</h1>", html)
        self.assertIn("page_bans", html)
        self.assertNotIn(">封锁记录</a>", html)
        self.assertNotIn(">IP 黑/白名单</a>", html)
        self.assertIn('id="abDetectedLogpaths"', html)
        self.assertIn(".ab-detected-logpaths{overflow-wrap:anywhere;word-break:break-all", html)
        self.assertIn("class=\"autoban-simple-controls\"", html)
        self.assertIn(".autoban-simple-controls{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr)", html)
        self.assertIn("class=\"autoban-simple-protect\"", html)
        self.assertIn("class=\"autoban-simple-preset\"", html)

    def test_installer_supports_console_and_agent_roles(self):
        self.assertIn('--role ROLE', self.source)
        self.assertIn("WAF_PANEL_ROLE", self.source)
        self.assertIn("WAF_AGENT_TOKEN", self.source)
        self.assertIn("nodes.py", self.source)
        self.assertIn("--role agent", self.source)
        self.assertIn("python3 -m venv", self.source)
        self.assertIn("import ensurepip", self.source)
        self.assertIn("python${pyver}-venv", self.source)
        self.assertIn("清理缺少 pip 的 Python 环境", self.source)
        self.assertIn("EnvironmentFile=", self.source)
        self.assertIn("systemctl is-active", self.source)
        self.assertIn("/agent/health", self.source)


if __name__ == "__main__":
    unittest.main()
