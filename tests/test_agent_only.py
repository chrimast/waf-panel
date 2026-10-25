import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))


class AgentOnlyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (PROJECT_DIR / "main.py").read_text()
        cls.config = (PROJECT_DIR / "config.py").read_text()
        cls.install = (PROJECT_DIR / "install.sh").read_text()
        cls.readme = (PROJECT_DIR / "README.md").read_text()

    def test_default_role_is_agent(self):
        self.assertIn('PANEL_ROLE = os.environ.get("WAF_PANEL_ROLE", "agent")', self.config)
        self.assertIn('ROLE="agent"', self.install)
        self.assertNotIn('ROLE="console"', self.install)
        self.assertNotIn("--password VALUE", self.install)
        self.assertIn("--role ROLE", self.install)

    def test_process_has_no_console_login_or_html_ui(self):
        self.assertNotIn("/login", self.main)
        self.assertNotIn("templates/index.html", self.main)
        self.assertNotIn("LOGIN_HTML", self.main)
        self.assertNotIn("/api/nodes", self.main)
        self.assertNotIn("/api/password", self.main)
        self.assertFalse((PROJECT_DIR / "templates" / "index.html").exists())
        self.assertFalse((PROJECT_DIR / "nodes.py").exists())
        self.assertFalse((PROJECT_DIR / "password.py").exists())

    def test_agent_health_does_not_depend_on_local_node_store(self):
        self.assertIn('return {"ok": True, "role": "agent"}', self.main)
        self.assertNotIn("get_node", self.main)
        self.assertNotIn("forward_agent_request", self.main)

    def test_readme_is_agent_only(self):
        self.assertIn("--role agent", self.readme)
        self.assertIn("curl -fsSL https://raw.githubusercontent.com/chrimast/waf-panel/main/uninstall.sh | sudo bash", self.readme)
        self.assertIn("仅确认要删除整个", self.readme)
        self.assertIn("--purge-data", self.readme)
        self.assertNotIn("http://服务器IP:10087/login", self.readme)
        self.assertNotIn("本机总控", self.readme)
        self.assertIn("CF-Monitor", self.readme)
        self.assertIn("http://公网IP:10087", self.readme)
        self.assertNotIn("不要把 `http://IP:10087` 填进 CF-Monitor", self.readme)

    def test_logs_sql_avoids_distinct_concat_and_alias_order(self):
        sql = self.main
        self.assertIn("GROUP BY i.value", sql)
        self.assertIn("ORDER BY COUNT(*) DESC", sql)
        self.assertNotIn("GROUP_CONCAT(DISTINCT", sql)
        self.assertIn("GROUP_CONCAT(r.value)", sql)
        self.assertIn("GROUP_CONCAT(u.value)", sql)
        self.assertNotIn("MIN(a.time)", sql)
        self.assertNotIn("MAX(a.time)", sql)
        self.assertIn("/api/autoban_detect_logpaths", sql)
        self.assertIn("读取攻击日志失败", sql)

    def test_sqlite_text_factory_replaces_invalid_utf8(self):
        self.assertIn("text_factory", self.config)
        self.assertIn('decode("utf-8", "replace")', self.config)

    def test_sqlite_reads_invalid_utf8_uri_without_raising(self):
        import sqlite3
        import config
        db = sqlite3.connect(":memory:")
        config.configure_sqlite(db)
        self.assertEqual(db.text_factory(b"/hello.world?\xad d"), "/hello.world?\ufffd d")
        db.execute("CREATE TABLE uris (value TEXT)")
        db.execute("INSERT INTO uris(value) VALUES (CAST(X'2F68656C6C6F3FAD' AS TEXT))")
        value = db.execute("SELECT value FROM uris").fetchone()[0]
        self.assertIsInstance(value, str)
        self.assertTrue(value.startswith("/hello"))
        self.assertIn("\ufffd", value)

    def test_agent_token_is_required_from_env(self):
        import config

        with patch.dict(os.environ, {"WAF_AGENT_TOKEN": "env-token"}, clear=False):
            import importlib
            importlib.reload(config)
            self.assertTrue(config.verify_agent_token("env-token"))
            self.assertFalse(config.verify_agent_token("wrong"))
