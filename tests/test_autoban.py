import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, "/opt/waf-panel")

from autoban import (
    default_autoban_config,
    generate_custom_filter_files,
    generate_fail2ban_files,
    load_autoban_config,
    missing_jail_filters,
    remove_managed_jails,
    save_autoban_config,
)


class AutobanConfigTests(unittest.TestCase):
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
