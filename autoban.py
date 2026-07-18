import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

PANEL_DIR = Path("/opt/waf-panel")
AUTOBAN_CONFIG_PATH = PANEL_DIR / "autoban.json"
FAIL2BAN_JAIL_PATH = Path("/etc/fail2ban/jail.d/waf-panel-autoban.local")
FAIL2BAN_FILTER_PATH = Path("/etc/fail2ban/filter.d/waf-panel-autoban.conf")
MANAGED_JAILS_START = "# WAF-PANEL-START"
MANAGED_JAILS_END = "# WAF-PANEL-END"
FAIL2BAN_WAF_ACTION_PATH = Path("/etc/fail2ban/action.d/1panel-waf-blacklist.conf")
FAIL2BAN_CF_ACTION_PATH = Path("/etc/fail2ban/action.d/waf-panel-cloudflare.conf")
FAIL2BAN_JAIL_LOCAL_PATH = Path("/etc/fail2ban/jail.local")
NGINX_REAL_IP_SNIPPET_PATH = PANEL_DIR / "generated/cloudflare-real-ip.conf"
WAF_BLACKLIST_SCRIPT = PANEL_DIR / "scripts/fail2ban_waf_blacklist.py"
WAF_RULES_PATH = Path("/opt/1panel/apps/openresty/openresty/1pwaf/data/rules/ipBlack.json")
OPENRESTY_CONTAINER = "1Panel-openresty-bGB2"


def default_autoban_config():
    return {
        "enabled": False,
        "jail_name": "waf-panel-autoban",
        "filter_name": "waf-panel-autoban",
        "port": "80,443",
        "maxretry": 5,
        "findtime": 600,
        "bantime": 3600,
        "status_codes": [403, 429],
        "logpaths": [
            "/opt/1panel/apps/openresty/openresty/log/*.log",
            "/opt/1panel/www/sites/*/log/*.log",
        ],
        "ignore_regex": r"^.*(/(?:robots\.txt|favicon\.ico|.*\.(?:jpg|png|gif|jpeg|svg|webp|bmp|tiff|css|js|woff|woff2|eot|ttf|otf)))",
        "ignore_ips": ["127.0.0.1/8"],
        "local_ban": True,
        "banaction": "iptables-allports",
        "chain": "DOCKER-USER",
        "cloudflare_ban": False,
        "waf_blacklist": True,
        "cloudflare_email": "",
        "cloudflare_api_key": "",
        "cloudflare_note": "WAF Panel AutoBan",
        "cf_real_ip_enabled": True,
        "real_ip_header": "CF-Connecting-IP",
        "real_ip_recursive": True,
        "cf_real_ip_ranges": [
            "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
            "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
            "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
            "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
            "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
            "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
            "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
        ],
        "jails": [
            {"name": "docker-nginx-cc", "enabled": True, "filter": "nginx-cc", "maxretry": 5, "findtime": 600, "bantime": 3600},
            {"name": "docker-nginx-badbots", "enabled": True, "filter": "apache-badbots", "maxretry": 2, "findtime": 600, "bantime": 3600},
            {"name": "docker-nginx-botsearch", "enabled": True, "filter": "nginx-botsearch", "maxretry": 5, "findtime": 600, "bantime": 3600},
            {"name": "docker-nginx-http-auth", "enabled": True, "filter": "nginx-http-auth", "maxretry": 5, "findtime": 600, "bantime": 3600},
            {"name": "docker-nginx-limit-req", "enabled": True, "filter": "nginx-limit-req", "maxretry": 5, "findtime": 600, "bantime": 3600},
            {"name": "docker-php-url-fopen", "enabled": True, "filter": "php-url-fopen", "maxretry": 5, "findtime": 600, "bantime": 3600},
        ],
    }


def load_autoban_config(path=AUTOBAN_CONFIG_PATH):
    cfg = default_autoban_config()
    path = Path(path)
    if path.exists():
        with open(path) as f:
            loaded = json.load(f)
        if isinstance(loaded, dict):
            cfg.update(loaded)
    return normalize_autoban_config(cfg)


def save_autoban_config(cfg, path=AUTOBAN_CONFIG_PATH):
    cfg = normalize_autoban_config(cfg)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.chmod(path, 0o600)
    return cfg


def normalize_autoban_config(cfg):
    base = default_autoban_config()
    base.update(cfg or {})
    for key in ("maxretry", "findtime", "bantime"):
        base[key] = int(base.get(key) or default_autoban_config()[key])
    base["status_codes"] = [int(x) for x in _as_list(base.get("status_codes")) if str(x).strip().isdigit()]
    if not base["status_codes"]:
        base["status_codes"] = [403, 429]
    base["logpaths"] = [str(x).strip() for x in _as_list(base.get("logpaths")) if str(x).strip()]
    port = str(base.get("port") or "80,443").strip()
    port_aliases = {"http": "80", "https": "443"}
    base["port"] = ",".join(port_aliases.get(item.strip(), item.strip()) for item in port.split(",") if item.strip())
    base["ignore_ips"] = [str(x).strip() for x in _as_list(base.get("ignore_ips")) if str(x).strip()]
    base["cf_real_ip_ranges"] = [str(x).strip() for x in _as_list(base.get("cf_real_ip_ranges")) if str(x).strip()]
    base["jails"] = [_normalize_jail(x) for x in _as_list(base.get("jails")) if isinstance(x, dict)]
    for key in ("enabled", "local_ban", "cloudflare_ban", "waf_blacklist", "cf_real_ip_enabled", "real_ip_recursive"):
        base[key] = bool(base.get(key))
    base["banaction"] = str(base.get("banaction") or "iptables-allports").strip()
    base["chain"] = str(base.get("chain") or "DOCKER-USER").strip()
    return base


def _normalize_jail(jail):
    return {
        "name": str(jail.get("name", "")).strip(),
        "enabled": bool(jail.get("enabled", True)),
        "filter": str(jail.get("filter", "nginx-cc")).strip(),
        "maxretry": int(jail.get("maxretry") or 5),
        "findtime": int(jail.get("findtime") or 600),
        "bantime": int(jail.get("bantime") or 3600),
    }


def _as_list(value):
    if isinstance(value, list):
        return value
    if value is None:
        return []
    if isinstance(value, str):
        return [x.strip() for x in value.replace("\r", "").split("\n") if x.strip()]
    return [value]


def generate_fail2ban_files(cfg):
    cfg = normalize_autoban_config(cfg)
    codes = "|".join(str(c) for c in cfg["status_codes"])
    logpaths = "\n          ".join(cfg["logpaths"])
    actions = []
    if cfg["local_ban"]:
        actions.append(f"{cfg['banaction']}[chain={cfg['chain']}]")
    if cfg["cloudflare_ban"]:
        actions.append("waf-panel-cloudflare")
    if cfg["waf_blacklist"]:
        actions.append("1panel-waf-blacklist")
    action_text = "\n         ".join(actions) if actions else ""
    ignoreip = " ".join(cfg["ignore_ips"])
    enabled = "true" if cfg["enabled"] else "false"

    jail = f"""[{cfg['jail_name']}]
enabled = {enabled}
filter = {cfg['filter_name']}
port = {cfg['port']}
logpath = {logpaths}
maxretry = {cfg['maxretry']}
findtime = {cfg['findtime']}
bantime = {cfg['bantime']}
banaction = {cfg['banaction']}
chain = {cfg['chain']}
ignoreip = {ignoreip}
action = {action_text}
"""
    jail_local = generate_jail_local(cfg, action_text, logpaths, ignoreip)
    additional_jails = generate_additional_jails(cfg, action_text, logpaths, ignoreip)
    filter_conf = f"""[Definition]
failregex = ^<HOST> .* HTTP.* ({codes}) .*$
ignoreregex = {cfg['ignore_regex']}
"""
    nginx_real_ip = generate_nginx_real_ip(cfg)
    waf_action = f"""[Definition]
actionban = /usr/bin/python3 {WAF_BLACKLIST_SCRIPT} ban <ip>
actionunban = /usr/bin/python3 {WAF_BLACKLIST_SCRIPT} unban <ip>

[Init]
"""
    cf_action = f"""[Definition]
actionban = curl -s -o /dev/null -X POST <_cf_api_prms> -d '{{"mode":"block","configuration":{{"target":"ip","value":"<ip>"}},"notes":"{cfg['cloudflare_note']} <name>"}}' <_cf_api_url>
actionunban = id=$(curl -s -X GET <_cf_api_prms> "<_cf_api_url>?mode=block&configuration_target=ip&configuration_value=<ip>&page=1&per_page=1&notes={cfg['cloudflare_note'].replace(' ', '%%20')}%%20<name>" | {{ jq -r '.result[0].id' 2>/dev/null || tr -d '\\n' | sed -nE 's/^.*"result"\\s*:\\s*\\[\\s*\\{{\\s*"id"\\s*:\\s*"([^"]+)".*$/\\1/p'; }}); if [ -z "$id" ]; then exit 0; fi; curl -s -o /dev/null -X DELETE <_cf_api_prms> "<_cf_api_url>/$id"
_cf_api_url = https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules
_cf_api_prms = -H 'X-Auth-Email: <cfuser>' -H 'X-Auth-Key: <cftoken>' -H 'Content-Type: application/json'

[Init]
cfuser = {cfg['cloudflare_email']}
cftoken = {cfg['cloudflare_api_key']}
"""
    return {"jail": jail, "jail_local": jail_local, "managed_jails": jail + "\n" + additional_jails, "filter": filter_conf, "waf_action": waf_action, "cloudflare_action": cf_action, "nginx_real_ip": nginx_real_ip}


def generate_jail_local(cfg, action_text, logpaths, ignoreip):
    parts = [f"""# Managed by waf-panel
[DEFAULT]
bantime = {cfg['bantime']}
findtime = {cfg['findtime']}
maxretry = {cfg['maxretry']}
banaction = {cfg['banaction']}
chain = {cfg['chain']}
action = {action_text}
"""]
    for jail in cfg["jails"]:
        if not jail.get("name"):
            continue
        parts.append(f"""[{jail['name']}]
enabled = {'true' if cfg['enabled'] and jail['enabled'] else 'false'}
filter = {jail['filter']}
port = {cfg['port']}
logpath = {logpaths}
maxretry = {jail['maxretry']}
findtime = {jail['findtime']}
bantime = {jail['bantime']}
banaction = {cfg['banaction']}
chain = {cfg['chain']}
ignoreip = {ignoreip}
action = {action_text}
""")
    return "\n".join(parts)


def generate_additional_jails(cfg, action_text, logpaths, ignoreip):
    parts = []
    for jail in cfg["jails"]:
        if not jail.get("name"):
            continue
        parts.append(f"""[{jail['name']}]
enabled = {'true' if cfg['enabled'] and jail['enabled'] else 'false'}
filter = {jail['filter']}
port = {cfg['port']}
logpath = {logpaths}
maxretry = {jail['maxretry']}
findtime = {jail['findtime']}
bantime = {jail['bantime']}
banaction = {cfg['banaction']}
chain = {cfg['chain']}
ignoreip = {ignoreip}
action = {action_text}
""")
    return "\n".join(parts)


def remove_managed_jails(existing):
    start = existing.find(MANAGED_JAILS_START)
    end = existing.find(MANAGED_JAILS_END)
    if start < 0 or end < start:
        return existing
    end += len(MANAGED_JAILS_END)
    return (existing[:start].rstrip() + "\n" + existing[end:].lstrip("\n")).rstrip() + "\n"


def generate_nginx_real_ip(cfg):
    if not cfg.get("cf_real_ip_enabled"):
        return ""
    lines = ["# Managed by waf-panel: Cloudflare real IP"]
    lines += [f"set_real_ip_from {item};" for item in cfg["cf_real_ip_ranges"]]
    lines.append(f"real_ip_header {cfg.get('real_ip_header') or 'CF-Connecting-IP'};")
    lines.append(f"real_ip_recursive {'on' if cfg.get('real_ip_recursive') else 'off'};")
    return "\n".join(lines) + "\n"


def _backup_file(path):
    path = Path(path)
    if not path.exists(): return None
    backup = path.with_name(f"{path.name}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}")
    shutil.copy2(path, backup)
    return backup


def apply_autoban_config(cfg):
    cfg = save_autoban_config(cfg)
    files = generate_fail2ban_files(cfg)
    FAIL2BAN_JAIL_PATH.parent.mkdir(parents=True, exist_ok=True)
    FAIL2BAN_FILTER_PATH.parent.mkdir(parents=True, exist_ok=True)
    FAIL2BAN_WAF_ACTION_PATH.parent.mkdir(parents=True, exist_ok=True)
    backup = _backup_file(FAIL2BAN_JAIL_PATH)
    FAIL2BAN_JAIL_PATH.write_text(files["managed_jails"].strip() + "\n")
    FAIL2BAN_FILTER_PATH.write_text(files["filter"])
    FAIL2BAN_WAF_ACTION_PATH.write_text(files["waf_action"])
    FAIL2BAN_CF_ACTION_PATH.write_text(files["cloudflare_action"])
    NGINX_REAL_IP_SNIPPET_PATH.parent.mkdir(parents=True, exist_ok=True)
    NGINX_REAL_IP_SNIPPET_PATH.write_text(files["nginx_real_ip"])
    os.chmod(FAIL2BAN_CF_ACTION_PATH, 0o600)
    ensure_waf_blacklist_script()

    check = subprocess.run(["fail2ban-client", "-t"], capture_output=True, text=True)
    if check.returncode != 0:
        if backup:
            shutil.copy2(backup, FAIL2BAN_JAIL_PATH)
        else:
            FAIL2BAN_JAIL_PATH.unlink(missing_ok=True)
        raise RuntimeError((check.stdout + check.stderr).strip() or "Fail2ban 配置校验失败")
    return cfg


def migrate_autoban_to_dedicated_jail():
    if not FAIL2BAN_JAIL_LOCAL_PATH.exists():
        return False
    existing = FAIL2BAN_JAIL_LOCAL_PATH.read_text()
    cleaned = remove_managed_jails(existing)
    if cleaned == existing:
        return False
    _backup_file(FAIL2BAN_JAIL_LOCAL_PATH)
    FAIL2BAN_JAIL_LOCAL_PATH.write_text(cleaned)
    return True


def ensure_waf_blacklist_script():
    WAF_BLACKLIST_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
    WAF_BLACKLIST_SCRIPT.write_text(WAF_BLACKLIST_SCRIPT_CONTENT)
    os.chmod(WAF_BLACKLIST_SCRIPT, 0o755)


def restart_fail2ban():
    out = subprocess.run(["systemctl", "restart", "fail2ban"], capture_output=True, text=True)
    return {"ok": out.returncode == 0, "output": (out.stdout + out.stderr).strip()}


def fail2ban_status(jail_name=None):
    cmd = ["fail2ban-client", "status"] + ([jail_name] if jail_name else [])
    out = subprocess.run(cmd, capture_output=True, text=True)
    return {"ok": out.returncode == 0, "output": (out.stdout + out.stderr).strip()}


WAF_BLACKLIST_SCRIPT_CONTENT = r'''#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path

WAF_RULES_PATH = Path("/opt/1panel/apps/openresty/openresty/1pwaf/data/rules/ipBlack.json")
RELOAD_CMD = ["docker", "exec", "1Panel-openresty-bGB2", "/usr/local/openresty/nginx/sbin/nginx", "-s", "reload"]

def load_rules():
    if not WAF_RULES_PATH.exists():
        return {"rules": []}
    with open(WAF_RULES_PATH) as f:
        data = json.load(f)
    if not isinstance(data, dict):
        data = {"rules": data if isinstance(data, list) else []}
    data.setdefault("rules", [])
    return data

def value(rule):
    if isinstance(rule, str): return rule
    if not isinstance(rule, dict): return ""
    typ = rule.get("type")
    if typ in ("ipv4", "ipv6"): return rule.get(typ, "")
    if typ == "ipGroup": return rule.get("ipGroup", "")
    if typ == "ipArr": return f"{rule.get('ipStart','')}-{rule.get('ipEnd','')}"
    return rule.get("ipv4") or rule.get("ipv6") or rule.get("ipGroup") or ""

def make_rule(ip):
    if ":" in ip:
        return {"name":"fail2ban","state":"on","type":"ipv6","ipv4":"","ipv6":ip,"ipStart":"","ipEnd":"","ipGroup":"","description":"fail2ban auto ban"}
    if "/" in ip:
        return {"name":"fail2ban","state":"on","type":"ipGroup","ipv4":"","ipv6":"","ipStart":"","ipEnd":"","ipGroup":ip,"description":"fail2ban auto ban"}
    return {"name":"fail2ban","state":"on","type":"ipv4","ipv4":ip,"ipv6":"","ipStart":"","ipEnd":"","ipGroup":"","description":"fail2ban auto ban"}

def save_rules(data):
    tmp = WAF_RULES_PATH.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, WAF_RULES_PATH)
    subprocess.run(RELOAD_CMD, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("ban", "unban"):
        print("usage: fail2ban_waf_blacklist.py ban|unban IP", file=sys.stderr)
        return 2
    op, ip = sys.argv[1], sys.argv[2]
    data = load_rules()
    if op == "ban":
        if ip not in {value(r) for r in data["rules"]}:
            data["rules"].append(make_rule(ip))
            save_rules(data)
    else:
        new_rules = [r for r in data["rules"] if value(r) != ip]
        if len(new_rules) != len(data["rules"]):
            data["rules"] = new_rules
            save_rules(data)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''
