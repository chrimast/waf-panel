import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

os.environ.setdefault("WAF_PANEL_PASSWORD", "test-password")
os.environ.setdefault("WAF_PANEL_HOME", str(PROJECT_DIR))


class NodeStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        import nodes

        self.nodes = nodes
        self._orig = nodes.NODES_STORE
        nodes.NODES_STORE = Path(self.tmp.name) / "nodes.json"
        self.addCleanup(lambda: setattr(nodes, "NODES_STORE", self._orig))

    def test_default_local_node_is_created(self):
        items = self.nodes.list_nodes()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "local")
        self.assertEqual(items[0]["kind"], "local")
        self.assertEqual(items[0]["name"], "本机")
        self.assertNotIn("token", items[0])
        secret = self.nodes.get_node("local")
        self.assertTrue(secret["token"])

    def test_add_remote_node_keeps_token_private(self):
        with patch.object(self.nodes, "http_request", return_value=type("R", (), {"status_code": 200, "json": lambda self=None: {"ok": True}})()):
            node = self.nodes.add_node(name="香港 1", url="http://192.0.2.8:10087", token="remote-agent-token")
        self.assertEqual(node["kind"], "remote")
        self.assertEqual(node["url"], "http://192.0.2.8:10087")
        self.assertNotIn("token", node)
        stored = self.nodes.get_node(node["id"])
        self.assertEqual(stored["token"], "remote-agent-token")
        self.nodes.select_node(node["id"])
        self.assertEqual(self.nodes.current_node_id(), node["id"])

    def test_local_node_status_is_online(self):
        items = self.nodes.list_nodes()
        self.assertTrue(items[0]["online"])
        self.assertEqual(items[0]["status"], "online")
        self.assertEqual(items[0]["message"], "本机直连")

    def test_remote_node_probe_reports_online_offline_and_bad_token(self):
        captured = []

        class FakeResponse:
            def __init__(self, status_code, data):
                self.status_code = status_code
                self._payload = data

            def json(self):
                return self._payload

        def fake_request(method, url, headers=None, payload=None, timeout=None):
            captured.append({"method": method, "url": url, "headers": headers, "timeout": timeout})
            if "192.0.2.8" in url:
                return FakeResponse(200, {"ok": True, "role": "agent"})
            if "192.0.2.9" in url:
                return FakeResponse(401, {"error": True, "message": "Agent Token 无效"})
            return FakeResponse(502, {"error": True, "message": "timed out"})

        with patch.object(self.nodes, "http_request", fake_request):
            ok = self.nodes.add_node("香港 1", "http://192.0.2.8:10087", "good-token")
            bad_token = self.nodes.add_node("香港 2", "http://192.0.2.9:10087", "bad-token")
            down = self.nodes.add_node("香港 3", "http://192.0.2.10:10087", "any-token")
            listed = {item["id"]: item for item in self.nodes.list_nodes()}

        self.assertTrue(ok["online"])
        self.assertEqual(ok["status"], "online")
        self.assertEqual(ok["message"], "连接正常")
        self.assertFalse(bad_token["online"])
        self.assertEqual(bad_token["status"], "auth")
        self.assertIn("Token", bad_token["message"])
        self.assertFalse(down["online"])
        self.assertEqual(down["status"], "offline")
        self.assertTrue(listed[ok["id"]]["online"])
        self.assertFalse(listed[bad_token["id"]]["online"])
        health_calls = [item for item in captured if item["url"].endswith("/agent/health")]
        self.assertGreaterEqual(len(health_calls), 3)
        self.assertEqual(health_calls[0]["headers"]["Authorization"], "Bearer good-token")
        self.assertLessEqual(health_calls[0]["timeout"], 5)

    def test_agent_token_matches_local_or_explicit_secret(self):
        local = self.nodes.get_node("local")
        self.assertTrue(self.nodes.verify_agent_token(local["token"]))
        self.assertFalse(self.nodes.verify_agent_token("wrong"))
        with patch.dict(os.environ, {"WAF_AGENT_TOKEN": "explicit-token"}, clear=False):
            self.assertTrue(self.nodes.verify_agent_token("explicit-token"))


class NodeProxyTests(unittest.TestCase):
    def test_remote_forward_uses_agent_path_and_bearer(self):
        import nodes

        captured = {}

        class FakeResponse:
            status_code = 200
            def json(self):
                return {"waf_state": "on"}

        def fake_request(method, url, headers=None, payload=None, timeout=None):
            captured.update(method=method, url=url, headers=headers, json=payload, timeout=timeout)
            return FakeResponse()

        node = {"id": "n1", "kind": "remote", "url": "http://192.0.2.8:10087/", "token": "remote-agent-token"}
        with patch.object(nodes, "http_request", fake_request):
            body, status = nodes.forward_agent_request(node, "GET", "/api/dashboard", None)

        self.assertEqual(status, 200)
        self.assertEqual(body["waf_state"], "on")
        self.assertEqual(captured["method"], "GET")
        self.assertEqual(captured["url"], "http://192.0.2.8:10087/agent/api/dashboard")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer remote-agent-token")

    def test_local_node_is_not_forwarded(self):
        import nodes

        with self.assertRaises(nodes.LocalNodeError):
            nodes.forward_agent_request({"id": "local", "kind": "local"}, "GET", "/api/dashboard", None)


class RoleConfigTests(unittest.TestCase):
    def test_agent_role_hides_console_paths(self):
        import config

        with patch.object(config, "PANEL_ROLE", "agent"):
            self.assertTrue(config.is_agent_role())
            self.assertFalse(config.console_path_allowed("/login"))
            self.assertFalse(config.console_path_allowed("/"))
            self.assertTrue(config.console_path_allowed("/agent/health"))
            self.assertTrue(config.console_path_allowed("/agent/api/dashboard"))


if __name__ == "__main__":
    unittest.main()
