import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import sys
sys.path.insert(0, "/opt/waf-panel")

import autoban
from autoban import (
    apply_autoban_config,
    default_autoban_config,
    generate_custom_filter_files,
    generate_fail2ban_files,
    load_autoban_config,
    missing_jail_filters,
    normalize_autoban_config,
    remove_managed_jails,
    save_autoban_config,
    test_filter_definition,
    validate_autoban_config,
)


class AutobanConfigTests(unittest.TestCase):
    def _apply_paths(self, root):
        return patch.multiple(
            autoban,
            AUTOBAN_CONFIG_PATH=root / "autoban.json",
            FAIL2BAN_JAIL_PATH=root / "jail.d/waf-panel-autoban.local",
            FAIL2BAN_FILTER_PATH=root / "filter.d/waf-panel-autoban.conf",
            FAIL2BAN_WAF_ACTION_PATH=root / "action.d/1panel-waf-blacklist.conf",
            FAIL2BAN_CF_ACTION_PATH=root / "action.d/waf-panel-cloudflare.conf",
            NGINX_REAL_IP_SNIPPET_PATH=root / "generated/cloudflare-real-ip.conf",
            WAF_BLACKLIST_SCRIPT=root / "scripts/fail2ban_waf_blacklist.py",
        )

    def test_generate_fail2ban_files_includes_editable_values_and_local_firewall(self):
        cfg = default_autoban_config()
        cfg.update({
            "enabled": True,
            "jail_name": "waf-auto-ban",
            "filter_name": "waf-auto-ban",
            "maxretry": 7,
            "findtime": 900,
            "bantime": 7200,
            "logpaths": ["/tmp/access.log", "/tmp/site.log"],
            "port": "http,https,2222",
            "status_codes": [403, 429, 444],
            "ignore_regex": "^.*static.*$",
            "ignore_ips": ["127.0.0.1/8", "192.0.2.1"],
            "local_ban": True,
            "banaction": "iptables-allports",
            "chain": "DOCKER-USER",
            "cloudflare_ban": True,
            "waf_blacklist": True,
            "cloudflare_email": "user@example.com",
            "cloudflare_api_key": "secret-key",
            "cloudflare_note": "WAF AutoBan",
        })

        files = generate_fail2ban_files(cfg)

        self.assertIn("[waf-auto-ban]", files["jail"])
        self.assertIn("maxretry = 7", files["jail"])
        self.assertIn("findtime = 900", files["jail"])
        self.assertIn("bantime = 7200", files["jail"])
        self.assertIn("/tmp/access.log", files["jail"])
        self.assertIn("port = 80,443,2222", files["jail"])
        self.assertIn("banaction = iptables-allports", files["jail"])
        self.assertIn("chain = DOCKER-USER", files["jail"])
        self.assertIn("iptables-allports", files["jail"])
        self.assertIn("banaction = iptables-allports", files["jail_local"])
        self.assertIn("chain = DOCKER-USER", files["jail_local"])
        self.assertIn("waf-panel-cloudflare", files["jail"])
        self.assertIn("1panel-waf-blacklist", files["jail"])
        self.assertIn("(403|429|444)", files["filter"])
        self.assertIn("^.*static.*$", files["filter"])
        self.assertIn("cfuser = user@example.com", files["cloudflare_action"])
        self.assertIn("cftoken = secret-key", files["cloudflare_action"])

    def test_generate_legacy_f2bv2_sections_are_editable(self):
        cfg = default_autoban_config()
        cfg.update({
            "cf_real_ip_enabled": True,
            "cf_real_ip_ranges": ["203.0.113.0/24", "2001:db8::/32"],
            "real_ip_header": "CF-Connecting-IP",
            "jails": [
                {"name": "docker-nginx-cc", "enabled": True, "filter": "nginx-cc", "maxretry": 5, "findtime": 600, "bantime": 3600},
                {"name": "docker-nginx-badbots", "enabled": False, "filter": "apache-badbots", "maxretry": 2, "findtime": 600, "bantime": 3600},
            ],
        })

        files = generate_fail2ban_files(cfg)

        self.assertIn("set_real_ip_from 203.0.113.0/24;", files["nginx_real_ip"])
        self.assertIn("set_real_ip_from 2001:db8::/32;", files["nginx_real_ip"])
        self.assertIn("real_ip_header CF-Connecting-IP;", files["nginx_real_ip"])
        self.assertIn("[docker-nginx-cc]", files["jail_local"])
        self.assertIn("[docker-nginx-badbots]", files["jail_local"])
        self.assertIn("enabled = false", files["jail_local"])
        self.assertIn("filter = nginx-cc", files["jail_local"])
        self.assertIn("filter = apache-badbots", files["jail_local"])

    def test_additional_jail_can_override_shared_runtime_values(self):
        cfg = default_autoban_config()
        cfg["jails"] = [{
            "name": "app-login",
            "enabled": True,
            "filter": "nginx-cc",
            "logpaths": ["/srv/app/login.log"],
            "port": "8443",
            "ignore_ips": ["198.51.100.0/24"],
            "maxretry": 3,
            "findtime": 120,
            "bantime": 900,
            "local_ban": False,
            "waf_blacklist": True,
            "cloudflare_ban": False,
        }]

        section = generate_fail2ban_files(cfg)["managed_jails"].split("[app-login]", 1)[1]

        self.assertIn("logpath = /srv/app/login.log", section)
        self.assertIn("port = 8443", section)
        self.assertIn("ignoreip = 198.51.100.0/24", section)
        self.assertIn("action = 1panel-waf-blacklist", section)
        self.assertNotIn("action = iptables-allports", section.splitlines())

    def test_additional_jail_can_override_backend_firewall_action_and_chain(self):
        cfg = default_autoban_config()
        cfg["jails"] = [{
            "name": "journal-login", "enabled": True, "filter": "nginx-cc",
            "backend": "systemd", "journalmatch": "_SYSTEMD_UNIT=app.service",
            "banaction": "iptables-multiport", "chain": "INPUT",
        }]

        section = generate_fail2ban_files(cfg)["managed_jails"].split("[journal-login]", 1)[1]

        self.assertIn("backend = systemd", section)
        self.assertIn("journalmatch = _SYSTEMD_UNIT=app.service", section)
        self.assertNotIn("logpath =", section)
        self.assertIn("banaction = iptables-multiport", section)
        self.assertIn("chain = INPUT", section)
        self.assertIn("iptables-multiport[chain=INPUT]", section)

    def test_validate_rejects_system_filter_collision_and_disabled_missing_reference(self):
        cfg = default_autoban_config()
        cfg["custom_filters"] = [{"name": "sshd", "failregex": "^<HOST>$"}]
        with self.assertRaisesRegex(ValueError, "系统 Filter"):
            validate_autoban_config(cfg, installed={"sshd"})

        cfg = default_autoban_config()
        cfg["jails"] = [{"name": "disabled", "enabled": False, "filter": "missing-filter"}]
        with self.assertRaisesRegex(ValueError, "missing-filter"):
            validate_autoban_config(cfg, installed=set())

        cfg = default_autoban_config()
        cfg["jails"] = []
        cfg["custom_filters"] = [{"name": "empty", "failregex": ""}]
        with self.assertRaisesRegex(ValueError, "failregex"):
            validate_autoban_config(cfg, installed=set())

        cfg = default_autoban_config()
        cfg["jails"] = [{"name": "journal", "filter": "nginx-cc", "backend": "systemd"}]
        with self.assertRaisesRegex(ValueError, "journalmatch"):
            validate_autoban_config(cfg, installed={"nginx-cc"})

    def test_normalize_rejects_duplicate_and_main_jail_names(self):
        cfg = default_autoban_config()
        cfg["jails"] = [
            {"name": "duplicate", "filter": "nginx-cc"},
            {"name": "duplicate", "filter": "nginx-cc"},
        ]
        with self.assertRaisesRegex(ValueError, "重复 Jail"):
            normalize_autoban_config(cfg)

        cfg["jails"] = [{"name": cfg["jail_name"], "filter": "nginx-cc"}]
        with self.assertRaisesRegex(ValueError, "主 Jail"):
            normalize_autoban_config(cfg)

    def test_normalize_rejects_duplicate_filter_names_and_missing_host(self):
        cfg = default_autoban_config()
        cfg["custom_filters"] = [
            {"name": "same", "failregex": "^<HOST>$"},
            {"name": "same", "failregex": "^<HOST> blocked$"},
        ]
        with self.assertRaisesRegex(ValueError, "重复 Filter"):
            normalize_autoban_config(cfg)

        cfg["custom_filters"] = [{"name": "no-host", "failregex": "^blocked$"}]
        with self.assertRaisesRegex(ValueError, "<HOST>"):
            normalize_autoban_config(cfg)

    def test_filter_definition_uses_fail2ban_regex_with_temporary_file(self):
        result = Mock(returncode=0, stdout="Success, the total number of match is 1\n203.0.113.9", stderr="")
        with patch.object(autoban.subprocess, "run", return_value=result) as run:
            tested = test_filter_definition(
                {"name": "login", "failregex": "^<HOST> failed$", "ignoreregex": ""},
                "203.0.113.9 failed\n",
            )

        self.assertTrue(tested["ok"])
        self.assertEqual(tested["matches"], 1)
        self.assertEqual(tested["hosts"], ["203.0.113.9"])
        command = run.call_args.args[0]
        self.assertEqual(command[0], "fail2ban-regex")
        self.assertEqual(command[1], "-")
        self.assertTrue(command[2].endswith(".conf"))
        self.assertEqual(run.call_args.kwargs["input"], "203.0.113.9 failed\n")

    def test_normalize_preserves_port_and_does_not_manage_ssh_jail(self):
        cfg = default_autoban_config()
        cfg["port"] = "22,3389"
        files = generate_fail2ban_files(cfg)
        self.assertIn("port = 22,3389", files["jail"])
        self.assertNotIn("[sshd]", files["jail_local"])

    def test_normalize_migrates_named_web_ports_to_numeric_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "autoban.json"
            path.write_text('{"port":"http,https"}')

            loaded = load_autoban_config(path)

            self.assertEqual(loaded["port"], "80,443")

    def test_save_and_load_round_trip_preserves_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "autoban.json"
            cfg = default_autoban_config()
            cfg["cloudflare_email"] = "ops@example.com"
            cfg["cloudflare_api_key"] = "token-value"

            save_autoban_config(cfg, path)
            loaded = load_autoban_config(path)

            self.assertEqual(loaded["cloudflare_email"], "ops@example.com")
            self.assertEqual(loaded["cloudflare_api_key"], "token-value")

    def test_remove_managed_jails_preserves_1panel_config(self):
        original = """#DEFAULT-START
[DEFAULT]
bantime = 600
#DEFAULT-END

[sshd]
enabled = true
port = 2233

# WAF-PANEL-START
[waf-panel-autoban]
enabled = false
# WAF-PANEL-END
"""

        cleaned = remove_managed_jails(original)

        self.assertIn("[DEFAULT]", cleaned)
        self.assertIn("[sshd]", cleaned)
        self.assertIn("port = 2233", cleaned)
        self.assertNotIn("WAF-PANEL", cleaned)
        self.assertNotIn("[waf-panel-autoban]", cleaned)

    def test_default_config_carries_nginx_cc_filter(self):
        cfg = default_autoban_config()

        custom_filter = next(item for item in cfg["custom_filters"] if item["name"] == "nginx-cc")

        self.assertIn("^<HOST> .* HTTP.* (403|429) .*$", custom_filter["failregex"])
        self.assertIn("robots", custom_filter["ignoreregex"])

    def test_generate_custom_filter_files_renders_definition(self):
        cfg = default_autoban_config()
        cfg["custom_filters"] = [{
            "name": "nginx-cc",
            "failregex": "^<HOST> blocked$",
            "ignoreregex": "^<HOST> allowed$",
        }]

        files = generate_custom_filter_files(cfg)

        self.assertEqual(set(files), {"nginx-cc"})
        self.assertIn("[Definition]", files["nginx-cc"])
        self.assertIn("failregex = ^<HOST> blocked$", files["nginx-cc"])
        self.assertIn("ignoreregex = ^<HOST> allowed$", files["nginx-cc"])

    def test_apply_removes_filter_deleted_from_saved_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_cfg = default_autoban_config()
            old_cfg["custom_filters"] = [{"name": "old-filter", "failregex": "^<HOST>$", "ignoreregex": ""}]
            old_cfg["jails"] = []
            save_autoban_config(old_cfg, root / "autoban.json")
            old_filter = root / "filter.d/old-filter.conf"
            old_filter.parent.mkdir(parents=True)
            old_filter.write_text("old content")
            new_cfg = dict(old_cfg, custom_filters=[])

            with self._apply_paths(root), patch.object(autoban.subprocess, "run", return_value=Mock(returncode=0, stdout="", stderr="")):
                apply_autoban_config(new_cfg)

            self.assertFalse(old_filter.exists())
            self.assertEqual(load_autoban_config(root / "autoban.json")["custom_filters"], [])

    def test_apply_restores_deleted_filter_when_validation_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_cfg = default_autoban_config()
            old_cfg["custom_filters"] = [{"name": "old-filter", "failregex": "^<HOST>$", "ignoreregex": ""}]
            old_cfg["jails"] = []
            save_autoban_config(old_cfg, root / "autoban.json")
            old_filter = root / "filter.d/old-filter.conf"
            old_filter.parent.mkdir(parents=True)
            old_filter.write_text("old content")
            new_cfg = dict(old_cfg, custom_filters=[])

            with self._apply_paths(root), patch.object(autoban.subprocess, "run", return_value=Mock(returncode=1, stdout="", stderr="invalid")):
                with self.assertRaisesRegex(RuntimeError, "invalid"):
                    apply_autoban_config(new_cfg)

            self.assertEqual(old_filter.read_text(), "old content")
            names = [item["name"] for item in load_autoban_config(root / "autoban.json")["custom_filters"]]
            self.assertEqual(names, ["old-filter"])

    def test_apply_restores_every_managed_file_when_validation_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = [
                root / "jail.d/waf-panel-autoban.local",
                root / "filter.d/waf-panel-autoban.conf",
                root / "action.d/1panel-waf-blacklist.conf",
                root / "action.d/waf-panel-cloudflare.conf",
                root / "generated/cloudflare-real-ip.conf",
                root / "scripts/fail2ban_waf_blacklist.py",
            ]
            for index, path in enumerate(paths):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"original-{index}")
            save_autoban_config(default_autoban_config(), root / "autoban.json")

            with self._apply_paths(root), patch.object(autoban.subprocess, "run", return_value=Mock(returncode=1, stdout="", stderr="invalid")):
                with self.assertRaisesRegex(RuntimeError, "invalid"):
                    apply_autoban_config(default_autoban_config())

            self.assertEqual([path.read_text() for path in paths], [f"original-{i}" for i in range(len(paths))])

    def test_apply_restores_every_managed_file_when_a_write_step_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = [
                root / "jail.d/waf-panel-autoban.local",
                root / "filter.d/waf-panel-autoban.conf",
                root / "action.d/1panel-waf-blacklist.conf",
                root / "action.d/waf-panel-cloudflare.conf",
                root / "generated/cloudflare-real-ip.conf",
                root / "scripts/fail2ban_waf_blacklist.py",
            ]
            for index, path in enumerate(paths):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"original-{index}")
            save_autoban_config(default_autoban_config(), root / "autoban.json")

            with self._apply_paths(root), patch.object(autoban, "ensure_waf_blacklist_script", side_effect=OSError("disk error")):
                with self.assertRaisesRegex(RuntimeError, "disk error"):
                    apply_autoban_config(default_autoban_config())

            self.assertEqual([path.read_text() for path in paths], [f"original-{i}" for i in range(len(paths))])

    def test_apply_rejects_deleting_filter_used_by_enabled_jail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_cfg = default_autoban_config()
            old_cfg["custom_filters"] = [{"name": "old-filter", "failregex": "^<HOST>$", "ignoreregex": ""}]
            old_cfg["jails"] = [{"name": "uses-old", "enabled": True, "filter": "old-filter"}]
            save_autoban_config(old_cfg, root / "autoban.json")
            old_filter = root / "filter.d/old-filter.conf"
            old_filter.parent.mkdir(parents=True)
            old_filter.write_text("old content")
            new_cfg = dict(old_cfg, custom_filters=[])

            with self._apply_paths(root):
                with self.assertRaisesRegex(RuntimeError, "old-filter"):
                    apply_autoban_config(new_cfg)

            self.assertEqual(old_filter.read_text(), "old content")

    def test_missing_jail_filters_uses_custom_and_installed_filters(self):
        cfg = default_autoban_config()
        cfg["jails"] = [
            {"name": "cc", "enabled": True, "filter": "nginx-cc"},
            {"name": "bots", "enabled": True, "filter": "nginx-botsearch"},
            {"name": "missing", "enabled": True, "filter": "not-installed"},
        ]

        missing = missing_jail_filters(cfg, installed={"nginx-botsearch"})

        self.assertEqual(missing, ["not-installed"])

    def test_generated_managed_jails_include_main_and_json_jails(self):
        cfg = default_autoban_config()
        cfg["jails"] = [
            {"name": "docker-nginx-cc", "enabled": True, "filter": "nginx-cc", "maxretry": 4, "findtime": 300, "bantime": 900}
        ]

        managed = generate_fail2ban_files(cfg)["managed_jails"]

        self.assertIn("[waf-panel-autoban]", managed)
        self.assertIn("filter = waf-panel-autoban", managed)
        self.assertIn("[docker-nginx-cc]", managed)
        self.assertIn("filter = nginx-cc", managed)
        self.assertIn("bantime = 900", managed)


if __name__ == "__main__":
    unittest.main()
