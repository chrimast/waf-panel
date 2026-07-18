import os
import tempfile
import time
import unittest
from pathlib import Path

import sys
sys.path.insert(0, "/opt/waf-panel")

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


class WafPanelTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = Path("/opt/waf-panel/templates/index.html").read_text()

    def test_dashboard_integrates_map_and_geo_controls(self):
        self.assertIn('id="dashboardMap"', self.template)
        self.assertIn('id="geoAction"', self.template)
        self.assertIn('id="asnInput"', self.template)
        self.assertIn("Promise.all([api('dashboard'),api('map'),api('geo_config')])", self.template)
        self.assertLess(self.template.index('dashboard-recent'), self.template.index('id="geoAction"'))

    def test_map_and_geo_are_removed_from_sidebar(self):
        self.assertNotIn("nav('mapview')", self.template)
        self.assertNotIn("nav('geo')", self.template)

    def test_attack_log_table_has_stable_scroll_layout(self):
        self.assertIn('class="table-scroll attack-log-table"', self.template)
        self.assertIn(".attack-log-table table{min-width:", self.template)
        self.assertIn(".cell-clip", self.template)

    def test_attack_logs_have_independent_temporary_and_permanent_controls(self):
        self.assertIn("临时封禁", self.template)
        self.assertIn("永久黑名单", self.template)
        self.assertIn("toggleLogBan(${r.id},'${r.ip||''}','temporary'", self.template)
        self.assertIn("toggleLogBan(${r.id},'${r.ip||''}','permanent'", self.template)

    def test_autoban_uses_port_and_preset_selects(self):
        self.assertNotIn(">1Panel Fail2ban</h3>", self.template)
        self.assertNotIn('id="pServiceEnabled"', self.template)
        self.assertNotIn('id="pSshEnabled"', self.template)
        self.assertNotIn('id="pSshPort"', self.template)
        self.assertNotIn('id="pSshLogpath"', self.template)
        self.assertIn("启用 WAF 自动封禁", self.template)
        self.assertIn(">主 Jail</h3>", self.template)
        self.assertIn("自定义 Filters（JSON，可编辑）", self.template)
        self.assertIn('id="abFilters"', self.template)
        self.assertIn("Filter 依赖", self.template)
        self.assertIn("/etc/fail2ban/filter.d/&lt;name&gt;.conf", self.template)
        self.assertIn("/etc/fail2ban/filter.d/nginx-cc.conf", self.template)
        self.assertIn("附加 Jails（JSON，可编辑）", self.template)
        self.assertIn("/etc/fail2ban/jail.d/waf-panel-autoban.local", self.template)
        self.assertIn("各 Jail 通过 filter 字段调用对应 Filter", self.template)
        self.assertIn('<label>监听端口</label><input id="abPort"', self.template)
        self.assertIn("c.port||'80,443'", self.template)
        self.assertIn('<select id="abBanaction">', self.template)
        for action in ("iptables-allports", "iptables-multiport", "firewallcmd-ipset", "ufw"):
            self.assertIn(f'<option value="{action}"', self.template)
        self.assertIn('<select id="abRealIpHeader">', self.template)
        for header in ("CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP", "True-Client-IP"):
            self.assertIn(f'<option value="{header}"', self.template)


if __name__ == "__main__":
    unittest.main()
