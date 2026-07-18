import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, "/opt/waf-panel")

from autoban import default_autoban_config, generate_fail2ban_files, save_autoban_config, load_autoban_config


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
        self.assertIn("port = http,https,2222", files["jail"])
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
        cfg["port"] = "http,https,22022"
        files = generate_fail2ban_files(cfg)
        self.assertIn("port = http,https,22022", files["jail"])
        self.assertNotIn("[sshd]", files["jail_local"])

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


if __name__ == "__main__":
    unittest.main()
