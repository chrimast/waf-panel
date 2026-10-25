import os
import tempfile
import time
import unittest
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main


class WafPanelRuleTests(unittest.TestCase):
    def test_make_ip_rule_defaults_enabled_and_1panel_shape(self):
        rule = main._make_ip_rule("203.0.113.9")

        self.assertEqual(rule["state"], "on")
        self.assertEqual(rule["type"], "ipv4")
        self.assertEqual(rule["ipv4"], "203.0.113.9")
        self.assertIn("name", rule)
        self.assertIn("description", rule)

    def test_toggle_rule_state_updates_existing_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            original_rules = main.WAF_RULES
            main.WAF_RULES = tmp
            try:
                path = Path(tmp) / "ipBlack.json"
                path.write_text('{"rules":[{"state":"off","type":"ipv4","ipv4":"203.0.113.9"}]}')

                changed = main._set_ip_rule_state("ipBlack", "203.0.113.9", "on")
                data = main.waf_read_json(str(path))

                self.assertTrue(changed)
                self.assertEqual(data["rules"][0]["state"], "on")
            finally:
                main.WAF_RULES = original_rules

    def test_attack_map_query_joins_attached_ips_database(self):
        sql = main._attack_map_sql()

        self.assertIn("ip.ips", sql)
        self.assertIn("attack_logs", sql)

    def test_logs_sql_groups_by_ip_and_orders_by_count(self):
        sql = main._logs_sql()

        self.assertIn("GROUP BY i.value", sql)
        self.assertIn("COUNT(*)", sql)
        self.assertIn("MIN(", sql)
        self.assertIn("MAX(", sql)
        self.assertIn("ORDER BY COUNT(*) DESC", sql)
        self.assertNotIn("GROUP_CONCAT(DISTINCT", sql)
        self.assertIn("GROUP_CONCAT(r.value)", sql)
        self.assertIn("GROUP_CONCAT(u.value)", sql)
        self.assertIn("r.value", sql)
        self.assertIn("u.value", sql)

    def test_aggregate_attack_logs_merges_ip_with_time_range(self):
        rows = [
            {"ip": "203.0.113.9", "localtime": "2026-10-20 10:00:00", "time": 100, "rule": "xss", "uri": "/a", "host": "a.test", "is_block": 1},
            {"ip": "203.0.113.9", "localtime": "2026-10-20 12:00:00", "time": 200, "rule": "sql", "uri": "/b", "host": "b.test", "is_block": 1},
            {"ip": "198.51.100.7", "localtime": "2026-10-20 11:00:00", "time": 150, "rule": "cc", "uri": "/", "host": "c.test", "is_block": 0},
        ]

        data = main._aggregate_attack_logs(rows)

        self.assertEqual([item["ip"] for item in data], ["203.0.113.9", "198.51.100.7"])
        self.assertEqual(data[0]["count"], 2)
        self.assertEqual(data[0]["first_seen"], "2026-10-20 10:00:00")
        self.assertEqual(data[0]["last_seen"], "2026-10-20 12:00:00")
        self.assertEqual(data[1]["count"], 1)

    def test_log_ban_inserts_block_record_for_ip(self):
        self.assertIn("INSERT INTO block_ips", main._block_ip_sql())

    def test_temporary_rule_has_source_expiry_and_block_record(self):
        expires_at = int(time.time()) + 3600
        rule = main._make_temporary_ip_rule("203.0.113.10", expires_at, block_id=42)

        self.assertTrue(main._is_temporary_ip_rule(rule))
        self.assertEqual(main._temporary_rule_expiry(rule), expires_at)
        self.assertEqual(main._temporary_rule_block_id(rule), 42)
        self.assertEqual(main._ip_rule_value(rule), "203.0.113.10")

    def test_permanent_and_temporary_rules_are_independent(self):
        permanent = main._make_ip_rule("203.0.113.10")
        temporary = main._make_temporary_ip_rule("203.0.113.10", int(time.time()) + 3600)

        states = main._ip_ban_states([permanent, temporary], "203.0.113.10")

        self.assertEqual(states, {"temporary": True, "permanent": True})

    def test_expired_temporary_rule_cleanup_preserves_permanent_rule(self):
        permanent = main._make_ip_rule("203.0.113.10")
        expired = main._make_temporary_ip_rule("203.0.113.10", 100)
        active = main._make_temporary_ip_rule("203.0.113.11", 300)

        kept, expired_ips = main._filter_expired_temporary_rules(
            [permanent, expired, active], now=200
        )

        self.assertEqual([main._ip_rule_value(rule) for rule in kept], ["203.0.113.10", "203.0.113.11"])
        self.assertEqual(expired_ips, {"203.0.113.10"})


class WafPanelAutobanApiTests(unittest.TestCase):
    def test_catalog_marks_panel_and_system_filters_with_jail_references(self):
        cfg = main.load_autoban_config()
        cfg["custom_filters"] = [{"name": "owned", "failregex": "^<HOST>$", "ignoreregex": ""}]
        cfg["jails"] = [{"name": "login", "enabled": True, "filter": "owned"}]
        with patch.object(main, "load_autoban_config", return_value=cfg), patch.object(main, "installed_filter_names", return_value={"owned", "sshd"}):
            result = asyncio.run(main.autoban_catalog())

        by_name = {item["name"]: item for item in result["filters"]}
        self.assertEqual(by_name["owned"]["owner"], "panel")
        self.assertEqual(by_name["owned"]["used_by"], ["login"])
        self.assertEqual(by_name["sshd"]["owner"], "system")

    def test_filter_test_endpoint_returns_real_validator_result(self):
        request = AsyncMock()
        request.json.return_value = {"filter": {"name": "login", "failregex": "^<HOST>$"}, "sample": "203.0.113.9"}
        with patch.object(main, "test_filter_definition", return_value={"ok": True, "output": "1 matched"}) as test:
            result = asyncio.run(main.autoban_filter_test(request))

        self.assertTrue(result["ok"])
        test.assert_called_once()

    def test_validate_and_preview_do_not_write_configuration(self):
        request = AsyncMock()
        request.json.return_value = {"jails": [], "custom_filters": []}
        with patch.object(main, "validate_autoban_config", return_value={"jails": []}) as validate, patch.object(main, "generate_fail2ban_files", return_value={"managed_jails": "[demo]"}), patch.object(main, "generate_custom_filter_files", return_value={"demo": "[Definition]"}), patch.object(main, "apply_autoban_config") as apply:
            checked = asyncio.run(main.autoban_validate(request))
            preview = asyncio.run(main.autoban_preview(request))

        self.assertTrue(checked["ok"])
        self.assertEqual(preview["jail_local"], "[demo]")
        self.assertEqual(preview["filters"]["demo"], "[Definition]")
        self.assertFalse(apply.called)
        self.assertEqual(validate.call_count, 2)

    def test_per_jail_status_returns_parsed_runtime_data(self):
        status = {"ok": True, "running": True, "currently_banned": 2, "total_banned": 8, "banned_ips": ["203.0.113.9"]}
        cfg = main.load_autoban_config()
        cfg["jails"] = [{"name": "demo", "filter": "nginx-cc"}]
        with patch.object(main, "load_autoban_config", return_value=cfg), patch.object(main, "fail2ban_jail_status", return_value=status):
            result = asyncio.run(main.autoban_jail_status("demo"))

        self.assertTrue(result["running"])

    def test_autoban_config_reports_main_jail_generated_flag(self):
        with patch.object(main, "load_autoban_config", return_value={"jail_name": "waf-panel-autoban"}), patch.object(main, "fail2ban_status", return_value={"ok": True}), patch.object(main, "missing_jail_filters", return_value=[]), patch.object(main, "detect_default_logpaths", return_value=["/tmp/a.log"]), patch.object(main, "main_jail_generated", return_value=True):
            result = asyncio.run(main.autoban_config_get())
        self.assertTrue(result["main_jail_generated"])

    def test_manual_autoban_applies_merged_waf_result(self):
        request = AsyncMock()
        request.json.return_value = {"ip": "203.0.113.8"}
        with patch.object(main, "load_autoban_config", return_value={"jail_name": "waf-panel-autoban"}), patch.object(main.subprocess, "run", return_value=type("R", (), {"returncode": 0, "stdout": "1", "stderr": ""})()), patch.object(main, "apply_jail_waf_ban", return_value={"ok": True, "block_id": 9}) as apply:
            result = asyncio.run(main.autoban_ban(request))
        self.assertTrue(result["ok"])
        apply.assert_called_once_with("203.0.113.8")

    def test_manual_autoban_unban_applies_merged_waf_result(self):
        request = AsyncMock()
        request.json.return_value = {"ip": "203.0.113.8"}
        with patch.object(main, "load_autoban_config", return_value={"jail_name": "waf-panel-autoban"}), patch.object(main.subprocess, "run", return_value=type("R", (), {"returncode": 0, "stdout": "1", "stderr": ""})()), patch.object(main, "apply_jail_waf_unban", return_value={"ok": True}) as apply:
            result = asyncio.run(main.autoban_unban(request))
        self.assertTrue(result["ok"])
        apply.assert_called_once_with("203.0.113.8")


PROJECT_DIR = Path(__file__).resolve().parents[1]


class WafPanelTemplateTests(unittest.TestCase):
    def test_console_html_is_removed(self):
        self.assertFalse((PROJECT_DIR / "templates" / "index.html").exists())
        source = (PROJECT_DIR / "main.py").read_text()
        self.assertNotIn("/login", source)
        self.assertNotIn("templates/index.html", source)


if __name__ == "__main__":
    unittest.main()
