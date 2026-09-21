import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

PANEL_DIR = Path(os.environ.get("WAF_PANEL_HOME", Path(__file__).resolve().parent))
WAF_BASE = Path(os.environ.get("WAF_BASE", "/opt/1panel/apps/openresty/openresty/1pwaf/data"))
OPENRESTY_CONTAINER = os.environ.get("OR_CONTAINER", "1Panel-openresty-bGB2")
AUTOBAN_CONFIG_PATH = PANEL_DIR / "autoban.json"
FAIL2BAN_ROOT = Path(os.environ.get("FAIL2BAN_ROOT", "/etc/fail2ban"))
FAIL2BAN_JAIL_PATH = FAIL2BAN_ROOT / "jail.d/waf-panel-autoban.local"
FAIL2BAN_FILTER_PATH = FAIL2BAN_ROOT / "filter.d/waf-panel-autoban.conf"
MANAGED_JAILS_START = "# WAF-PANEL-START"
MANAGED_JAILS_END = "# WAF-PANEL-END"
FAIL2BAN_WAF_ACTION_PATH = FAIL2BAN_ROOT / "action.d/1panel-waf-blacklist.conf"
FAIL2BAN_CF_ACTION_PATH = FAIL2BAN_ROOT / "action.d/waf-panel-cloudflare.conf"
FAIL2BAN_JAIL_LOCAL_PATH = FAIL2BAN_ROOT / "jail.local"
NGINX_REAL_IP_SNIPPET_PATH = PANEL_DIR / "generated/cloudflare-real-ip.conf"
WAF_BLACKLIST_SCRIPT = PANEL_DIR / "scripts/fail2ban_waf_blacklist.py"
WAF_RULES_PATH = WAF_BASE / "rules/ipBlack.json"
PANEL_ROOT = Path(os.environ.get("PANEL_ROOT", "/opt/1panel"))
V1_OPENRESTY_LOG = "/opt/1panel/apps/openresty/openresty/log/*.log"
V1_SITE_LOG = "/opt/1panel/apps/openresty/openresty/www/sites/*/log/*.log"
V2_SITE_LOG = "/opt/1panel/www/sites/*/log/*.log"


def _openresty_dir(panel_root=None, waf_base=None):
    waf = Path(waf_base or WAF_BASE)
    if waf.name == "data" and waf.parent.name == "1pwaf":
        return waf.parent.parent
    return Path(panel_root or PANEL_ROOT) / "apps/openresty/openresty"


def _log_glob_available(glob_path):
    text = str(glob_path)
    if "/www/sites/" in text:
        return Path(text.split("/sites/")[0] + "/sites").is_dir()
    if text.endswith("/log/*.log"):
        log_dir = Path(text[: -len("/*.log")])
        return log_dir.is_dir() or log_dir.parent.is_dir()
    return Path(text).parent.is_dir()


def detect_default_logpaths(panel_root=None, waf_base=None):
    """Pick 1Panel v1 and/or v2 site logs that actually exist; keep both if neither is present."""
    root = Path(panel_root or PANEL_ROOT)
    or_dir = _openresty_dir(root, waf_base)
    candidates = [
        str(or_dir / "log" / "*.log"),
        str(or_dir / "www" / "sites" / "*" / "log" / "*.log"),
        str(root / "www" / "sites" / "*" / "log" / "*.log"),
    ]
    found = [path for path in candidates if _log_glob_available(path)]
    return found or [V1_OPENRESTY_LOG, V1_SITE_LOG, V2_SITE_LOG]


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
        "logpaths": detect_default_logpaths(),
        "ignore_regex": r"^.*(/(?:robots\.txt|favicon\.ico|.*\.(?:jpg|png|gif|jpeg|svg|webp|bmp|tiff|css|js|woff|woff2|eot|ttf|otf)))",
        "ignore_ips": ["127.0.0.1/8"],
        "custom_filters": [
            {
                "name": "nginx-cc",
                "failregex": r"^<HOST> .* HTTP.* (403|429) .*$",
                "ignoreregex": r"^.*(\/(?:robots\.txt|favicon\.ico|.*\.(?:jpg|png|gif|jpeg|svg|webp|bmp|tiff|css|js|woff|woff2|eot|ttf|otf))$)",
            }
        ],
        "local_ban": True,
        "banaction": "iptables-allports",
        "chain": "DOCKER-USER",
        "cloudflare_ban": False,
        "waf_blacklist": True,
        "cloudflare_email": "",
        "cloudflare_api_key": "",
        "cloudflare_note": "WAF 管理面板自动封禁",
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
            {"name": "docker-nginx-badbots", "enabled": False, "filter": "apache-badbots", "maxretry": 2, "findtime": 600, "bantime": 3600},
            {"name": "docker-nginx-botsearch", "enabled": False, "filter": "nginx-botsearch", "maxretry": 5, "findtime": 600, "bantime": 3600},
            {"name": "docker-nginx-http-auth", "enabled": False, "filter": "nginx-http-auth", "maxretry": 5, "findtime": 600, "bantime": 3600},
            {"name": "docker-nginx-limit-req", "enabled": False, "filter": "nginx-limit-req", "maxretry": 5, "findtime": 600, "bantime": 3600},
            {"name": "docker-php-url-fopen", "enabled": False, "filter": "php-url-fopen", "maxretry": 5, "findtime": 600, "bantime": 3600},
        ],
    }


def load_autoban_config(path=None):
    cfg = default_autoban_config()
    path = Path(path or AUTOBAN_CONFIG_PATH)
    if path.exists():
        with open(path) as f:
            loaded = json.load(f)
        if isinstance(loaded, dict):
            cfg.update(loaded)
    return normalize_autoban_config(cfg)


def save_autoban_config(cfg, path=None):
    cfg = normalize_autoban_config(cfg)
    path = Path(path or AUTOBAN_CONFIG_PATH)
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
    if not base["logpaths"]:
        base["logpaths"] = detect_default_logpaths()
    port = str(base.get("port") or "80,443").strip()
    port_aliases = {"http": "80", "https": "443"}
    base["port"] = ",".join(port_aliases.get(item.strip(), item.strip()) for item in port.split(",") if item.strip())
    base["ignore_ips"] = [str(x).strip() for x in _as_list(base.get("ignore_ips")) if str(x).strip()]
    base["cf_real_ip_ranges"] = [str(x).strip() for x in _as_list(base.get("cf_real_ip_ranges")) if str(x).strip()]
    base["custom_filters"] = [_normalize_custom_filter(x) for x in _as_list(base.get("custom_filters")) if isinstance(x, dict)]
    base["jails"] = [_normalize_jail(x) for x in _as_list(base.get("jails")) if isinstance(x, dict)]
    filter_names = set()
    for item in base["custom_filters"]:
        if item["name"] in filter_names:
            raise ValueError(f"重复 Filter 名称: {item['name']}")
        filter_names.add(item["name"])
        if item["failregex"] and "<HOST>" not in item["failregex"]:
            raise ValueError(f"Filter 必须包含 <HOST>: {item['name']}")
    jail_names = set()
    for jail in base["jails"]:
        if not jail["name"]:
            continue
        if jail["name"] == str(base.get("jail_name") or "").strip():
            raise ValueError(f"附加 Jail 不能使用主 Jail 名称: {jail['name']}")
        if jail["name"] in jail_names:
            raise ValueError(f"重复 Jail 名称: {jail['name']}")
        jail_names.add(jail["name"])
    for key in ("enabled", "local_ban", "cloudflare_ban", "waf_blacklist", "cf_real_ip_enabled", "real_ip_recursive"):
        base[key] = bool(base.get(key))
    base["banaction"] = str(base.get("banaction") or "iptables-allports").strip()
    base["chain"] = str(base.get("chain") or "DOCKER-USER").strip()
    return base


def _normalize_custom_filter(item):
    name = str(item.get("name", "")).strip()
    if name and not all(char.isalnum() or char in "_-" for char in name):
        raise ValueError(f"无效 Filter 名称: {name}")
    return {
        "name": name,
        "failregex": str(item.get("failregex", "")).strip(),
        "ignoreregex": str(item.get("ignoreregex", "")).strip(),
    }


def _normalize_jail(jail):
    actions = jail.get("actions") if isinstance(jail.get("actions"), dict) else {}
    return {
        "name": str(jail.get("name", "")).strip(),
        "enabled": bool(jail.get("enabled", True)),
        "filter": str(jail.get("filter", "nginx-cc")).strip(),
        "maxretry": int(jail.get("maxretry") or 5),
        "findtime": int(jail.get("findtime") or 600),
        "bantime": int(jail.get("bantime") or 3600),
        "logpaths": [str(x).strip() for x in _as_list(jail.get("logpaths")) if str(x).strip()],
        "port": str(jail.get("port") or "").strip(),
        "ignore_ips": [str(x).strip() for x in _as_list(jail.get("ignore_ips")) if str(x).strip()],
        "backend": str(jail.get("backend") or "auto").strip(),
        "journalmatch": str(jail.get("journalmatch") or "").strip(),
        "banaction": str(jail.get("banaction") or "").strip(),
        "chain": str(jail.get("chain") or "").strip(),
        "local_ban": jail.get("local_ban", actions.get("local_ban")),
        "waf_blacklist": jail.get("waf_blacklist", actions.get("waf_blacklist")),
        "cloudflare_ban": jail.get("cloudflare_ban", actions.get("cloudflare_ban")),
    }


def test_filter_definition(item, sample):
    item = _normalize_custom_filter(item)
    if not item["name"] or not item["failregex"]:
        raise ValueError("Filter 名称和 failregex 不能为空")
    with tempfile.NamedTemporaryFile("w", suffix=".conf", encoding="utf-8") as definition:
        definition.write("[Definition]\nfailregex = " + item["failregex"] + "\nignoreregex = " + item["ignoreregex"] + "\n")
        definition.flush()
        result = subprocess.run(
            ["fail2ban-regex", "-", definition.name],
            input=sample,
            capture_output=True,
            text=True,
        )
    output = (result.stdout + result.stderr).strip()
    match = re.search(r"total number of match is\s+(\d+)", output, re.I)
    hosts = sorted(set(re.findall(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])", output)))
    return {"ok": result.returncode == 0, "matches": int(match.group(1)) if match else 0, "hosts": hosts, "output": output}


# pytest must not collect this imported runtime helper as a test function.
test_filter_definition.__test__ = False


def _as_list(value):
    if isinstance(value, list):
        return value
    if value is None:
        return []
    if isinstance(value, str):
        return [x.strip() for x in value.replace("\r", "").split("\n") if x.strip()]
    return [value]


def generate_custom_filter_files(cfg):
    cfg = normalize_autoban_config(cfg)
    files = {}
    for item in cfg["custom_filters"]:
        if not item["name"] or not item["failregex"]:
            continue
        failregex = "\n            ".join(item["failregex"].splitlines())
        ignoreregex = "\n              ".join(item["ignoreregex"].splitlines())
        files[item["name"]] = f"[Definition]\nfailregex = {failregex}\nignoreregex = {ignoreregex}\n"
    return files


def installed_filter_names(directory=FAIL2BAN_FILTER_PATH.parent):
    directory = Path(directory)
    return {path.stem for path in directory.glob("*.conf")} if directory.exists() else set()


def missing_jail_filters(cfg, installed=None):
    cfg = normalize_autoban_config(cfg)
    available = set(installed if installed is not None else installed_filter_names())
    available.update(generate_custom_filter_files(cfg))
    available.add(cfg["filter_name"])
    required = {jail["filter"] for jail in cfg["jails"] if jail["filter"]}
    return sorted(required - available)


def validate_autoban_config(cfg, installed=None, panel_owned=None):
    cfg = normalize_autoban_config(cfg)
    installed = set(installed if installed is not None else installed_filter_names())
    panel_owned = set(panel_owned or ())
    custom_names = {item["name"] for item in cfg["custom_filters"]}
    empty = sorted(item["name"] or "未命名" for item in cfg["custom_filters"] if not item["failregex"])
    if empty:
        raise ValueError("Filter failregex 不能为空: " + ", ".join(empty))
    missing_journal = sorted(jail["name"] for jail in cfg["jails"] if jail["backend"] == "systemd" and not jail["journalmatch"])
    if missing_journal:
        raise ValueError("systemd Jail 必须设置 journalmatch: " + ", ".join(missing_journal))
    collisions = sorted(custom_names & (installed - panel_owned))
    if collisions:
        raise ValueError("自建 Filter 与系统 Filter 重名: " + ", ".join(collisions))
    missing = missing_jail_filters(cfg, installed=installed)
    if missing:
        raise ValueError("缺少 Fail2ban Filters: " + ", ".join(missing))
    return cfg


def removed_custom_filter_names(previous_cfg, cfg):
    previous = set(generate_custom_filter_files(previous_cfg))
    current = set(generate_custom_filter_files(cfg))
    return previous - current


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


def _jail_action_text(cfg, jail):
    actions = []
    banaction = jail.get("banaction") or cfg["banaction"]
    chain = jail.get("chain") or cfg["chain"]
    if jail.get("local_ban") if jail.get("local_ban") is not None else cfg["local_ban"]:
        actions.append(f"{banaction}[chain={chain}]")
    if jail.get("cloudflare_ban") if jail.get("cloudflare_ban") is not None else cfg["cloudflare_ban"]:
        actions.append("waf-panel-cloudflare")
    if jail.get("waf_blacklist") if jail.get("waf_blacklist") is not None else cfg["waf_blacklist"]:
        actions.append("1panel-waf-blacklist")
    return "\n         ".join(actions)


def _additional_jail_section(cfg, jail):
    logpaths = jail["logpaths"] or cfg["logpaths"]
    ignore_ips = jail["ignore_ips"] or cfg["ignore_ips"]
    port = jail["port"] or cfg["port"]
    action_text = _jail_action_text(cfg, jail)
    logpath_text = "\n          ".join(logpaths)
    ignoreip_text = " ".join(ignore_ips)
    backend = jail.get("backend") or "auto"
    banaction = jail.get("banaction") or cfg["banaction"]
    chain = jail.get("chain") or cfg["chain"]
    source = f"journalmatch = {jail['journalmatch']}" if backend == "systemd" and jail.get("journalmatch") else f"logpath = {logpath_text}"
    return f"""[{jail['name']}]
enabled = {'true' if cfg['enabled'] and jail['enabled'] else 'false'}
filter = {jail['filter']}
port = {port}
backend = {backend}
{source}
maxretry = {jail['maxretry']}
findtime = {jail['findtime']}
bantime = {jail['bantime']}
banaction = {banaction}
chain = {chain}
ignoreip = {ignoreip_text}
action = {action_text}
"""


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
        parts.append(_additional_jail_section(cfg, jail))
    return "\n".join(parts)


def generate_additional_jails(cfg, action_text, logpaths, ignoreip):
    return "\n".join(
        _additional_jail_section(cfg, jail)
        for jail in cfg["jails"]
        if jail.get("name")
    )


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
    try:
        cfg = normalize_autoban_config(cfg)
        previous_cfg = load_autoban_config()
    except (TypeError, ValueError) as exc:
        raise RuntimeError(str(exc))
    removed_filters = removed_custom_filter_names(previous_cfg, cfg)
    installed = installed_filter_names() - removed_filters
    try:
        cfg = validate_autoban_config(
            cfg,
            installed=installed,
            panel_owned={item["name"] for item in previous_cfg["custom_filters"]},
        )
    except ValueError as exc:
        raise RuntimeError(str(exc))

    files = generate_fail2ban_files(cfg)
    custom_filters = generate_custom_filter_files(cfg)
    FAIL2BAN_JAIL_PATH.parent.mkdir(parents=True, exist_ok=True)
    FAIL2BAN_FILTER_PATH.parent.mkdir(parents=True, exist_ok=True)
    FAIL2BAN_WAF_ACTION_PATH.parent.mkdir(parents=True, exist_ok=True)
    managed_paths = (
        FAIL2BAN_JAIL_PATH, FAIL2BAN_FILTER_PATH, FAIL2BAN_WAF_ACTION_PATH,
        FAIL2BAN_CF_ACTION_PATH, NGINX_REAL_IP_SNIPPET_PATH, WAF_BLACKLIST_SCRIPT,
    )
    snapshots = {path: path.read_bytes() if path.exists() else None for path in managed_paths}
    jail_backup = _backup_file(FAIL2BAN_JAIL_PATH)
    filter_backups = {}
    for name in custom_filters.keys() | removed_filters:
        path = FAIL2BAN_FILTER_PATH.parent / f"{name}.conf"
        filter_backups[path] = _backup_file(path)
    try:
        for name, content in custom_filters.items():
            (FAIL2BAN_FILTER_PATH.parent / f"{name}.conf").write_text(content)
        for name in removed_filters:
            (FAIL2BAN_FILTER_PATH.parent / f"{name}.conf").unlink(missing_ok=True)
        FAIL2BAN_JAIL_PATH.write_text(files["managed_jails"].strip() + "\n")
        FAIL2BAN_FILTER_PATH.write_text(files["filter"])
        FAIL2BAN_WAF_ACTION_PATH.write_text(files["waf_action"])
        FAIL2BAN_CF_ACTION_PATH.write_text(files["cloudflare_action"])
        NGINX_REAL_IP_SNIPPET_PATH.parent.mkdir(parents=True, exist_ok=True)
        NGINX_REAL_IP_SNIPPET_PATH.write_text(files["nginx_real_ip"])
        os.chmod(FAIL2BAN_CF_ACTION_PATH, 0o600)
        ensure_waf_blacklist_script()

        check = _fail2ban_command(["-t"])
        if check.returncode != 0:
            raise RuntimeError((check.stdout + check.stderr).strip() or "Fail2ban 配置校验失败")
        return save_autoban_config(cfg)
    except Exception as exc:
        for path, content in snapshots.items():
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
        for path, backup in filter_backups.items():
            if backup:
                shutil.copy2(backup, path)
            else:
                path.unlink(missing_ok=True)
        if isinstance(exc, RuntimeError):
            raise
        raise RuntimeError(str(exc)) from exc


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


def _fail2ban_command(args):
    return subprocess.run(["fail2ban-client", *args], capture_output=True, text=True)


def restart_fail2ban():
    if os.environ.get("WAF_PANEL_DOCKER") == "1":
        out = _fail2ban_command(["reload"])
    else:
        out = subprocess.run(["systemctl", "restart", "fail2ban"], capture_output=True, text=True)
    return {"ok": out.returncode == 0, "output": (out.stdout + out.stderr).strip()}


def fail2ban_status(jail_name=None):
    cmd = ["fail2ban-client", "status"] + ([jail_name] if jail_name else [])
    out = subprocess.run(cmd, capture_output=True, text=True)
    return {"ok": out.returncode == 0, "output": (out.stdout + out.stderr).strip()}


def fail2ban_jail_status(jail_name):
    result = fail2ban_status(jail_name)
    output = result["output"]
    def number(label):
        match = re.search(rf"{re.escape(label)}:\s*(\d+)", output, re.I)
        return int(match.group(1)) if match else 0
    banned = re.search(r"Banned IP list:\s*(.*)", output, re.I)
    return {
        **result,
        "name": jail_name,
        "running": result["ok"],
        "currently_banned": number("Currently banned"),
        "total_banned": number("Total banned"),
        "banned_ips": banned.group(1).split() if banned and banned.group(1).strip() else [],
    }


WAF_BLACKLIST_SCRIPT_CONTENT = r'''#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path

WAF_RULES_PATH = Path(os.environ.get("WAF_BASE", "/opt/1panel/apps/openresty/openresty/1pwaf/data")) / "rules/ipBlack.json"
RELOAD_CMD = ["docker", "exec", os.environ.get("OR_CONTAINER", "1Panel-openresty-bGB2"), "/usr/local/openresty/nginx/sbin/nginx", "-s", "reload"]

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
