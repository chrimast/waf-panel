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

    def test_installer_creates_isolated_runtime(self):
        self.assertIn("python3 -m venv", self.source)
        self.assertIn("EnvironmentFile=", self.source)
        self.assertIn("systemctl is-active", self.source)
        self.assertIn("/login", self.source)


if __name__ == "__main__":
    unittest.main()
