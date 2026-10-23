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
                "WAF_PANEL_ROLE": "agent",
            }
        )
        code = (
            "import config; "
            "print(config.PANEL_HOME); print(config.WAF_BASE); "
            "print(config.OR_CONTAINER); print(config.PANEL_ROLE)"
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
                "agent",
            ],
        )

    def test_main_is_agent_only_without_html_assets(self):
        source = (PROJECT_DIR / "main.py").read_text()
        self.assertNotIn("StaticFiles", source)
        self.assertNotIn("templates/index.html", source)
        self.assertNotIn("/login", source)


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

    def test_installer_copies_autoban_with_renamed_jails(self):
        self.assertIn("autoban.py", self.source)
        autoban = (PROJECT_DIR / "autoban.py").read_text()
        self.assertIn('"name": "autoban-nginx-cc"', autoban)
        self.assertIn('"name": "autoban-php-url-fopen"', autoban)
        self.assertNotIn('"name": "docker-nginx-cc"', autoban)
        self.assertNotIn('"name": "docker-php-url-fopen"', autoban)
        self.assertEqual(autoban.count('"enabled": False'), 1)
        self.assertIn('"enabled": True, "filter": "apache-badbots"', autoban)
        self.assertIn('"enabled": True, "filter": "php-url-fopen"', autoban)


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
        self.assertIn("CF-Monitor", readme)
        self.assertFalse((PROJECT_DIR / "templates" / "index.html").exists())

    def test_installer_is_agent_only(self):
        self.assertIn('--role ROLE', self.source)
        self.assertIn("WAF_PANEL_ROLE", self.source)
        self.assertIn("WAF_AGENT_TOKEN", self.source)
        self.assertNotIn("nodes.py", self.source)
        self.assertNotIn("password.py", self.source)
        self.assertIn("--role agent", self.source)
        self.assertIn("python3 -m venv", self.source)
        self.assertIn("import ensurepip", self.source)
        self.assertIn("python${pyver}-venv", self.source)
        self.assertIn("清理缺少 pip 的 Python 环境", self.source)
        self.assertIn("EnvironmentFile=", self.source)
        self.assertIn("EnvironmentFile=-", self.source)
        self.assertIn("WAF_AGENT_TOKEN=", self.source)
        self.assertIn("systemctl is-active", self.source)
        self.assertIn("/agent/health", self.source)
        uninstall = (PROJECT_DIR / "uninstall.sh").read_text()
        self.assertIn("systemctl disable", uninstall)
        self.assertIn("--purge-data", uninstall)
        self.assertIn('"$PREFIX/.env"', uninstall)
        self.assertIn("未修改 1Panel", uninstall)


if __name__ == "__main__":
    unittest.main()
