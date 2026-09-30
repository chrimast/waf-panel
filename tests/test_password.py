import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

os.environ.setdefault("WAF_PANEL_PASSWORD", "initial-password")
os.environ.setdefault("WAF_PANEL_HOME", str(PROJECT_DIR))


class PasswordStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        import password as password_mod

        self.mod = password_mod
        self._orig = password_mod.PASSWORD_STORE
        password_mod.PASSWORD_STORE = Path(self.tmp.name) / "panel-password"
        self.addCleanup(lambda: setattr(password_mod, "PASSWORD_STORE", self._orig))
        if password_mod.PASSWORD_STORE.exists():
            password_mod.PASSWORD_STORE.unlink()

    def test_defaults_to_environment_password(self):
        with patch.dict(os.environ, {"WAF_PANEL_PASSWORD": "from-env"}, clear=False):
            self.assertEqual(self.mod.current_password(), "from-env")

    def test_change_password_requires_current_password(self):
        with patch.dict(os.environ, {"WAF_PANEL_PASSWORD": "from-env"}, clear=False):
            with self.assertRaisesRegex(ValueError, "当前密码不正确"):
                self.mod.change_password("wrong", "new-secret-1")

    def test_change_password_rejects_short_values(self):
        with patch.dict(os.environ, {"WAF_PANEL_PASSWORD": "from-env"}, clear=False):
            with self.assertRaisesRegex(ValueError, "至少 8"):
                self.mod.change_password("from-env", "short")

    def test_change_password_persists_and_replaces_initial_password(self):
        with patch.dict(os.environ, {"WAF_PANEL_PASSWORD": "from-env"}, clear=False):
            self.mod.change_password("from-env", "new-secret-1")
            self.assertEqual(self.mod.current_password(), "new-secret-1")
            self.assertEqual(self.mod.PASSWORD_STORE.read_text().strip(), "new-secret-1")
            self.assertTrue(self.mod.verify_password("new-secret-1"))
            self.assertFalse(self.mod.verify_password("from-env"))


class PasswordPageTests(unittest.TestCase):
    def test_admin_exposes_password_page(self):
        html = (PROJECT_DIR / "templates" / "index.html").read_text()
        self.assertIn("nav('password')", html)
        self.assertIn("总控登录密码", html)
        self.assertIn("不影响 Agent", html)
        self.assertIn('data-page="password"', html)
        self.assertIn("api('password'", html)
        source = (PROJECT_DIR / "main.py").read_text()
        self.assertIn('"/api/password"', source)
        self.assertIn("not path.startswith(\"/api/password\")", source)


if __name__ == "__main__":
    unittest.main()
