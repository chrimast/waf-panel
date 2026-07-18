import os
import tempfile
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


if __name__ == "__main__":
    unittest.main()
