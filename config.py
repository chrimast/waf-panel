"""
1Panel WAF 管理面板 - 配置
零侵入: 只读写 WAF 数据文件，不修改 1Panel 自身
"""
import os, json, sqlite3, subprocess, hashlib, hmac, base64, time

WAF_BASE = "/opt/1panel/apps/openresty/openresty/1pwaf/data"
WAF_CONF = os.path.join(WAF_BASE, "conf")
WAF_RULES = os.path.join(WAF_BASE, "rules")
WAF_DB = os.path.join(WAF_BASE, "db/waf")
WAF_GLOBAL_DB = os.path.join(WAF_BASE, "db/global")
WAF_DEFAULT = os.path.join(WAF_BASE, "default")
OR_CONTAINER = "1Panel-openresty-bGB2"
NGINX_RELOAD_CMD = f"docker exec {OR_CONTAINER} /usr/local/openresty/nginx/sbin/nginx -s reload"

PANEL_PASSWORD = "admin123"
SESSION_TTL = 86400

RULE_NAMES = {
    "waf": "WAF总开关", "xss": "XSS防护", "sql": "SQL注入防护",
    "cc": "CC攻击防护", "urlcc": "URL CC防护", "attackCount": "攻击次数限制",
    "notFoundCount": "404限制", "cookie": "Cookie注入", "header": "Header注入",
    "args": "参数过滤", "fileExt": "文件扩展名", "methodWhite": "请求方法白名单",
    "vuln": "漏洞规则", "strict": "严格模式", "bot": "机器人检测",
    "geoRestrict": "地理位置封禁", "allowSpider": "爬虫白名单",
    "ipWhite": "IP白名单", "ipBlack": "IP黑名单",
    "urlWhite": "URL白名单", "urlBlack": "URL黑名单",
    "uaWhite": "UA白名单", "uaBlack": "UA黑名单",
    "defaultUaBlack": "默认UA黑名单", "defaultUrlBlack": "默认URL黑名单",
    "defaultIpBlack": "默认IP黑名单", "app": "应用规则", "cdn": "CDN",
}

RULE_KEYS = ["xss","sql","cc","urlcc","attackCount","notFoundCount","cookie","header",
             "args","fileExt","methodWhite","vuln","strict","bot","app","geoRestrict",
             "allowSpider","ipWhite","ipBlack","urlWhite","urlBlack","uaWhite","uaBlack",
             "defaultUaBlack","defaultUrlBlack","defaultIpBlack"]

def waf_read_json(path):
    if not os.path.exists(path): return None
    with open(path) as f: return json.load(f)

def waf_write_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def nginx_reload():
    out = subprocess.run(NGINX_RELOAD_CMD, shell=True, capture_output=True, text=True)
    return {"reloaded": True, "output": out.stdout.strip() + out.stderr.strip()}

def db_connect(dbs=None, readonly=True):
    uri = f"file:{WAF_DB}/attack_logs.db?mode={'ro' if readonly else 'rw'}"
    db = sqlite3.connect(uri, uri=True)
    db.row_factory = sqlite3.Row
    if dbs is None: dbs = ["ip", "ru", "ur", "mv", "ho"]
    for alias in dbs:
        path = os.path.join(WAF_DB, f"{alias_map[alias]}.db")
        if os.path.exists(path):
            db.execute(f"ATTACH DATABASE '{path}' AS {alias}")
    return db

alias_map = {
    "ip": "ips", "ru": "rules", "ur": "uris", "rq": "req_uris",
    "ho": "hosts", "mv": "match_values", "rt": "rule_types",
    "nl": "nginx_logs", "ua": "user_agents",
    "is2": "ip_stats", "rs": "rule_stats",
}

def auth_secret():
    return hashlib.sha256(f"{PANEL_PASSWORD}|waf-panel".encode()).hexdigest()

def auth_make_token(ip: str):
    exp = int(time.time()) + SESSION_TTL
    payload = f"{exp}|{ip}"
    sig = hmac.new(auth_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.b64encode(f"{payload}|{sig}".encode()).decode()

def auth_verify_token(token: str) -> bool:
    try:
        decoded = base64.b64decode(token).decode()
        exp_str, ip, sig = decoded.split("|")
        if time.time() > int(exp_str): return False
        payload = f"{exp_str}|{ip}"
        expected = hmac.new(auth_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)
    except: return False
