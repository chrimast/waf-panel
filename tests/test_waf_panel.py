import os
import tempfile
import time
import unittest
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

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
        self.assertEqual(result["currently_banned"], 2)


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
        self.assertIn("删除被引用的 Filter 会被阻止", self.template)
        self.assertIn("/etc/fail2ban/filter.d/&lt;name&gt;.conf", self.template)
        self.assertIn("附加 Jails", self.template)
        self.assertIn("/etc/fail2ban/jail.d/waf-panel-autoban.local", self.template)
        self.assertIn("每个 Jail 可独立选择 Filter", self.template)
        self.assertIn('<label>设置端口</label><input id="abPort"', self.template)
        self.assertIn("c.port||'80,443'", self.template)
        self.assertIn('<select id="abBanaction">', self.template)
        for action in ("iptables-allports", "iptables-multiport", "firewallcmd-ipset", "ufw"):
            self.assertIn(f'<option value="{action}"', self.template)
        self.assertIn('<select id="abRealIpHeader"', self.template)
        for header in ("CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP", "True-Client-IP"):
            self.assertIn(f'<option value="{header}"', self.template)

    def test_autoban_page_has_operational_workbench_sections(self):
        self.assertIn('class="autoban-hero"', self.template)
        self.assertIn('class="autoban-summary-grid"', self.template)
        self.assertIn('class="autoban-policy-grid"', self.template)
        self.assertIn('class="autoban-jails-toolbar"', self.template)
        self.assertIn('id="abJailResources"', self.template)
        self.assertIn('自动封禁状态', self.template)
        self.assertIn('共享策略', self.template)
        self.assertIn('仅影响 WAF 自动封禁', self.template)

    def test_autoban_page_keeps_explicit_apply_boundary(self):
        self.assertIn('保存配置（不重启）', self.template)
        self.assertIn('应用配置并重启', self.template)
        self.assertIn('手动封禁', self.template)
        self.assertIn('手动解封', self.template)
        self.assertIn('aria-live="polite"', self.template)

    def test_autoban_page_has_structured_jail_and_filter_management(self):
        for marker in ('id="abJailResources"', 'id="abFilterResources"', 'id="abResourceEditor"'):
            self.assertIn(marker, self.template)
        for action in ('newAutobanJail', 'editAutobanJail', 'copyAutobanJail', 'deleteAutobanJail'):
            self.assertIn(action, self.template)
        for action in ('newAutobanFilter', 'editAutobanFilter', 'deleteAutobanFilter', 'testAutobanFilter'):
            self.assertIn(action, self.template)
        self.assertIn("此 Filter 正被以下 Jail 使用", self.template)
        self.assertIn("api('autoban_filter_test'", self.template)
        self.assertIn("api('autoban_catalog'", self.template)
        self.assertIn("renderAutobanResources();", self.template)

    def test_autoban_system_filters_are_browsed_in_read_only_modal(self):
        self.assertIn("查看系统 Filter", self.template)
        self.assertIn("showSystemFilters", self.template)
        self.assertIn('id="abSystemFilterSearch"', self.template)
        self.assertIn("renderSystemFilters", self.template)
        self.assertIn("f.owner==='panel'", self.template)
        self.assertIn("f.owner==='system'", self.template)
        self.assertIn("系统 Filter 仅供选择，不可在此修改", self.template)

    def test_autoban_uses_one_continuous_page(self):
        for marker in (
            "主 Jail", "共享策略", "附加 Jails", "自定义 Filter",
            "备份、检查与 Cloudflare（可选）", "运行操作",
        ):
            self.assertIn(marker, self.template)
        for obsolete in (
            'class="autoban-view-tabs"', 'id="autoban-view-overview"',
            'id="autoban-view-jails"', 'id="autoban-view-filters"',
            "switchAutobanView", 'id="abJailsView"', 'id="abFiltersView"',
        ):
            self.assertNotIn(obsolete, self.template)
        self.assertNotIn('<div class="autoban-resource-layout"><div id="abJailResources"', self.template)
        self.assertIn('<div class="autoban-resource-columns">', self.template)
        self.assertIn(".autoban-resource-columns{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))", self.template)
        self.assertIn("@media(max-width:900px){.autoban-resource-columns{grid-template-columns:1fr}", self.template)
        self.assertIn('<div id="abJailResources" class="autoban-resource-list"></div><div id="abResourceEditor"></div>', self.template)
        self.assertIn('<div id="abFilterResources" class="autoban-resource-list"></div><div id="abFilterResourceEditor"></div>', self.template)

    def test_autoban_keeps_operations_in_single_page_layout(self):
        for marker in (
            "copyAutobanFilter", "重命名时同步更新引用", "abEditJailBackend",
            "abEditJailJournal", "abEditJailBanaction", "abEditJailChain",
            "查看将写入的文件", "validateAutobanDraft", "exportAutobanConfig",
            "importAutobanConfig", "abDependencySummary", "abPreviewOutput",
            "currently_banned", "测试命中",
        ):
            self.assertIn(marker, self.template)
        self.assertIn("autobanEditor('jail')", self.template)
        self.assertIn("autobanEditor('filter')", self.template)

    def test_autoban_manual_operations_use_compact_aligned_controls(self):
        self.assertIn('class="autoban-manual"', self.template)
        self.assertIn('class="btn btn-danger btn-sm" onclick="manualAutoban(\'ban\')"', self.template)
        self.assertIn('class="btn btn-sm autoban-secondary" onclick="manualAutoban(\'unban\')"', self.template)
        self.assertIn('.autoban-manual{display:grid', self.template)
        self.assertIn('grid-template-columns:minmax(220px,1fr) auto auto', self.template)
        self.assertIn('.autoban-manual .btn{height:34px;min-width:72px;white-space:nowrap}', self.template)

    def test_autoban_advanced_tools_are_grouped_by_operator_intent(self):
        self.assertIn('备份、检查与 Cloudflare（可选）', self.template)
        self.assertIn('通常无需展开', self.template)
        self.assertIn('备份配置', self.template)
        self.assertIn('恢复备份', self.template)
        self.assertIn('Cloudflare 与真实 IP（可选）', self.template)
        self.assertIn('规则与诊断（通常无需修改）', self.template)
        self.assertIn('class="autoban-subsection"', self.template)
        self.assertIn("/etc/fail2ban/filter.d/&lt;name&gt;.conf", self.template)


if __name__ == "__main__":
    unittest.main()
