"""
1Panel WAF 管理面板 - FastAPI
零侵入: 直接读写 WAF 配置文件 + SQLite 日志，不修改 1Panel
"""
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import os, sqlite3, json, subprocess

from config import *
from autoban import (
    apply_autoban_config,
    fail2ban_status,
    load_autoban_config,
    restart_fail2ban,
)

app = FastAPI(title="WAF Panel")
app.mount("/static", StaticFiles(directory="/opt/waf-panel/static"), name="static")

# ── 认证中间件 ────────────────────────────────────
def get_token(request: Request) -> str:
    return request.cookies.get("waf_token", "")

def require_auth(request: Request):
    if request.url.path == "/login" or request.url.path.startswith("/static/"): return
    token = get_token(request)
    if not token or not auth_verify_token(token):
        # API 请求返回 401 JSON
        if request.url.path.startswith("/api"):
            raise HTTPException(401, detail="请先登录")
        # 页面请求跳转登录
        raise HTTPException(302, headers={"Location": "/login"})

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    try:
        require_auth(request)
    except HTTPException as e:
        if e.status_code == 302:
            return RedirectResponse("/login", 302)
        return JSONResponse({"error": True, "message": e.detail, "need_login": True}, e.status_code)
    return await call_next(request)

# ── 登录 ──────────────────────────────────────────
@app.get("/login", include_in_schema=False)
@app.post("/login", include_in_schema=False)
async def login_page(request: Request):
    if request.method == "POST":
        form = await request.form()
        password = form.get("password", "")
        if password == PANEL_PASSWORD:
            token = auth_make_token(request.client.host)
            resp = RedirectResponse("/", 302)
            resp.set_cookie("waf_token", token, max_age=SESSION_TTL, httponly=True)
            return resp
        return HTMLResponse(LOGIN_HTML.replace("{MSG}", '<p style="color:#e03131;text-align:center">密码错误</p>'))
    return HTMLResponse(LOGIN_HTML.replace("{MSG}", ""))

LOGIN_HTML = """<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>WAF Panel · 登录</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#1a1b1e;display:flex;align-items:center;justify-content:center;min-height:100vh}
form{background:#25262b;padding:40px;border-radius:12px;border:1px solid #373a40;width:360px}
h1{color:#fff;font-size:20px;text-align:center;margin-bottom:24px}
input{width:100%;padding:12px 16px;background:#1a1b1e;border:1px solid #373a40;color:#c1c2c5;border-radius:8px;font-size:15px;outline:none;margin-bottom:16px}
input:focus{border-color:#4c6ef5}
button{width:100%;padding:12px;background:#4c6ef5;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
button:hover{opacity:.85}
</style></head><body>
<form method="post"><h1>WAF 管理面板</h1>{MSG}<input type="password" name="password" placeholder="请输入访问密码" autofocus><button type="submit">登 录</button></form>
</body></html>"""

# ── 主页面 ────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    return open("/opt/waf-panel/templates/index.html").read()

# ── API: 仪表盘 ───────────────────────────────────
@app.get("/api/dashboard")
async def dashboard():
    data = {}
    # WAF 每日统计
    try:
        db = sqlite3.connect(f"file:{WAF_DB}/waf_stat.db?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT * FROM waf_stat ORDER BY day DESC LIMIT 30").fetchall()
        data["waf_stat"] = [dict(r) for r in rows]
        db.close()
    except: data["waf_stat"] = []

    # 跨库查询
    db = db_connect(["ip", "ru", "ur", "is2", "rs"])
    rows = db.execute("""
        SELECT s.*, l.value as rule_name FROM rs.rule_stats s
        LEFT JOIN ru.rules l ON l.id=s.resource_id ORDER BY s.date DESC LIMIT 20
    """).fetchall()
    data["rule_stats"] = [dict(r) for r in rows]

    rows = db.execute("""
        SELECT s.*, i.value as ip FROM is2.ip_stats s
        LEFT JOIN ip.ips i ON i.id=s.resource_id
        WHERE s.date=(SELECT MAX(date) FROM is2.ip_stats) ORDER BY s.count DESC LIMIT 10
    """).fetchall()
    data["top_ips"] = [dict(r) for r in rows]

    rows = db.execute("""
        SELECT a.id, a.localtime, a.is_block, i.value as ip, r.value as rule, u.value as uri
        FROM attack_logs a
        LEFT JOIN ip.ips i ON i.id=a.ip_id LEFT JOIN ru.rules r ON r.id=a.rule_id
        LEFT JOIN ur.uris u ON u.id=a.uri_id ORDER BY a.id DESC LIMIT 5
    """).fetchall()
    data["recent"] = [dict(r) for r in rows]
    db.close()

    global_conf = waf_read_json(os.path.join(WAF_CONF, "global.json"))
    data["waf_state"] = global_conf.get("waf", {}).get("state", "off") if global_conf else "off"
    data["waf_mode"] = global_conf.get("waf", {}).get("mode", "?") if global_conf else "?"
    return data

# ── API: 攻击日志 ─────────────────────────────────
@app.get("/api/logs")
async def logs(page: int = 1, limit: int = 20, search: str = ""):
    db = db_connect(["ip", "ru", "ur", "mv", "ho"])
    where = ""
    if search:
        where = f"WHERE i.value LIKE '%{search}%' OR r.value LIKE '%{search}%' OR u.value LIKE '%{search}%'"
    total = db.execute(f"SELECT COUNT(*) FROM attack_logs a LEFT JOIN ip.ips i ON i.id=a.ip_id LEFT JOIN ru.rules r ON r.id=a.rule_id LEFT JOIN ur.uris u ON u.id=a.uri_id {where}").fetchone()[0]
    rows = db.execute(f"""
        SELECT a.id, a.localtime, a.is_block, a.is_attack, a.time,
               i.value as ip, r.value as rule, u.value as uri,
               m.value as match_val, h.value as host
        FROM attack_logs a
        LEFT JOIN ip.ips i ON i.id=a.ip_id LEFT JOIN ru.rules r ON r.id=a.rule_id
        LEFT JOIN ur.uris u ON u.id=a.uri_id LEFT JOIN mv.match_values m ON m.id=a.match_value_id
        LEFT JOIN ho.hosts h ON h.id=a.host_id
        {where} ORDER BY a.id DESC LIMIT {limit} OFFSET {(page-1)*limit}
    """).fetchall()
    data = [dict(r) for r in rows]
    banned = {_ip_rule_value(rule) for rule in _read_blacklist_file("ipBlack")}
    for row in data:
        row["is_banned"] = row.get("ip") in banned
    db.close()
    return {"total": total, "page": page, "limit": limit, "pages": max(1, (total + limit - 1) // limit), "data": data}

# ── API: 日志详情 ─────────────────────────────────
@app.get("/api/log_detail")
async def log_detail(id: int):
    # 先查主表（5个attach）
    db = db_connect(["ip", "ru", "ur", "rq", "mv", "ho", "rt"])
    row = db.execute(f"""
        SELECT a.*, i.value as ip, r.value as rule, u.value as uri, req.value as req_uri,
               m.value as match_val, h.value as host, rt2.value as rule_type,
               a.nginx_log_id
        FROM attack_logs a
        LEFT JOIN ip.ips i ON i.id=a.ip_id LEFT JOIN ru.rules r ON r.id=a.rule_id
        LEFT JOIN ur.uris u ON u.id=a.uri_id LEFT JOIN rq.req_uris req ON req.id=a.req_uri_id
        LEFT JOIN mv.match_values m ON m.id=a.match_value_id LEFT JOIN ho.hosts h ON h.id=a.host_id
        LEFT JOIN rt.rule_types rt2 ON rt2.id=a.rule_type_id
        WHERE a.id={id}
    """).fetchone()
    if not row: raise HTTPException(404, "日志不存在")
    d = dict(row)
    nid = d.pop("nginx_log_id", 0)
    db.close()

    # 单独查 nginx_log + user_agent
    if nid:
        nl_db = sqlite3.connect(f"file:{WAF_DB}/nginx_logs.db?mode=ro", uri=True)
        nl_db.row_factory = sqlite3.Row
        nl_db.execute(f"ATTACH DATABASE '{WAF_DB}/user_agents.db' AS ua")
        nl_row = nl_db.execute(f"""
            SELECT nl.nginx_log, nl.status_code, nl.remote_port, ua2.value as user_agent
            FROM nginx_logs nl LEFT JOIN ua.user_agents ua2 ON ua2.id=nl.ua_id
            WHERE nl.id={nid}
        """).fetchone()
        if nl_row:
            d.update({k: nl_row[k] for k in nl_row.keys()})
        nl_db.close()

    # 提取方法
    log = d.get("nginx_log", "")
    if log:
        import re; m = re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b', log)
        if m: d["method"] = m.group(1)
    return d

# ── API: 封锁记录 ─────────────────────────────────
@app.get("/api/blocks")
async def blocks(page: int = 1, limit: int = 20):
    db = sqlite3.connect(f"file:{WAF_DB}/block_ips.db?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    db.execute(f"ATTACH DATABASE '{WAF_DB}/ips.db' AS ips")
    total = db.execute("SELECT COUNT(*) FROM block_ips").fetchone()[0]
    rows = db.execute(f"SELECT b.*, i.value as ip FROM block_ips b LEFT JOIN ips.ips i ON i.id=b.ip_id ORDER BY b.id DESC LIMIT {limit} OFFSET {(page-1)*limit}").fetchall()
    db.close()
    return {"total": total, "page": page, "limit": limit, "pages": max(1, (total+limit-1)//limit), "data": [dict(r) for r in rows]}

@app.post("/api/unblock")
async def unblock(request: Request):
    body = await request.json()
    db = sqlite3.connect(f"{WAF_DB}/block_ips.db")
    db.execute("DELETE FROM block_ips WHERE id=?", (body["id"],))
    db.commit(); db.close()
    return {"ok": True, "message": "已解除封锁"}

def _block_ip_sql():
    return "INSERT INTO block_ips (ip_id, is_block, blocking_time, attack_log_id, create_date) VALUES (?, 1, ?, ?, datetime('now', 'localtime'))"

@app.post("/api/log_ban")
async def log_ban(request: Request):
    body = await request.json()
    ip = str(body.get("ip", "")).strip()
    log_id = int(body.get("log_id") or 0)
    banned = bool(body.get("banned", True))
    if not ip:
        raise HTTPException(400, "日志没有有效 IP")

    rules = _read_blacklist_file("ipBlack")
    rules = [rule for rule in rules if _ip_rule_value(rule) != ip]
    if banned:
        rules.append(_make_ip_rule(ip))
    _write_blacklist_file("ipBlack", rules)

    db = sqlite3.connect(f"{WAF_DB}/ips.db")
    row = db.execute("SELECT id FROM ips WHERE value=?", (ip,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "IP 索引不存在")
    ip_id = row[0]

    db = sqlite3.connect(f"{WAF_DB}/block_ips.db")
    existing = db.execute("SELECT id FROM block_ips WHERE ip_id=? AND is_block=1", (ip_id,)).fetchone()
    if banned and not existing:
        db.execute(_block_ip_sql(), (ip_id, load_autoban_config().get("bantime", 3600), log_id))
    elif not banned:
        db.execute("DELETE FROM block_ips WHERE ip_id=?", (ip_id,))
    db.commit()
    db.close()
    action = "封禁" if banned else "解封"
    return {**{"ok": True, "message": f"已{action} {ip}"}, **nginx_reload()}

def _attack_map_sql():
    return """
        SELECT i.value as ip, COUNT(a.id) as count, MAX(a.localtime) as last_time
        FROM ip.ips i JOIN attack_logs a ON a.ip_id=i.id GROUP BY i.id ORDER BY count DESC LIMIT 200
    """

# ── API: 拦截地图 ─────────────────────────────────
@app.get("/api/map")
async def attack_map():
    db = db_connect(["ip"])
    rows = db.execute(_attack_map_sql()).fetchall()
    db.close()
    # 批量 GeoIP
    ips = [r["ip"] for r in rows]
    geo_data = {}
    import urllib.request
    for chunk in [ips[i:i+100] for i in range(0, len(ips), 100)]:
        try:
            req = urllib.request.Request("http://ip-api.com/batch", data=json.dumps([{"query": ip} for ip in chunk]).encode(),
                headers={"Content-Type": "application/json"})
            resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
            for item in resp:
                if item.get("status") == "success":
                    geo_data[item["query"]] = item
        except: pass
    points = []
    for r in rows:
        g = geo_data.get(r["ip"])
        if g:
            points.append({"ip": r["ip"], "lat": g["lat"], "lon": g["lon"], "country": g["country"],
                "city": g.get("city",""), "count": r["count"], "last_time": r["last_time"]})
    return {"points": points}

# ── API: 地理位置封禁 ─────────────────────────────
@app.get("/api/geo_config")
async def geo_get():
    g = waf_read_json(os.path.join(WAF_CONF, "global.json"))
    return g.get("geoRestrict", {}) if g else {}

@app.post("/api/geo_config")
async def geo_set(request: Request):
    body = await request.json()
    g = waf_read_json(os.path.join(WAF_CONF, "global.json"))
    if not g: raise HTTPException(500, "无法读取配置")
    g["geoRestrict"]["state"] = body.get("state", "off")
    g["geoRestrict"]["action"] = body.get("action", "deny")
    g["geoRestrict"]["rules"] = body.get("rules", [])
    waf_write_json(os.path.join(WAF_CONF, "global.json"), g)
    return {**{"ok": True, "message": "已保存"}, **nginx_reload()}

# ── API: 规则汇总 ─────────────────────────────────
@app.get("/api/rules")
async def rules_get():
    g = waf_read_json(os.path.join(WAF_CONF, "global.json"))
    rules = {}
    for k in RULE_KEYS:
        if k in g: rules[k] = g[k]
    rules["waf"] = g.get("waf", {})
    rules["cdn"] = g.get("cdn", {})
    return rules

# ── API: 规则开关 ─────────────────────────────────
@app.post("/api/rule_toggle")
async def rule_toggle(request: Request):
    body = await request.json()
    g = waf_read_json(os.path.join(WAF_CONF, "global.json"))
    if not g or body["rule"] not in g: raise HTTPException(404, "规则不存在")
    g[body["rule"]]["state"] = body["state"]
    waf_write_json(os.path.join(WAF_CONF, "global.json"), g)
    return {**{"ok": True, "message": "已更新"}, **nginx_reload()}

# ── API: CC 防护配置 ──────────────────────────────
@app.post("/api/cc_config")
async def cc_config(request: Request):
    body = await request.json()
    g = waf_read_json(os.path.join(WAF_CONF, "global.json"))
    if not g: raise HTTPException(500, "无法读取配置")
    for k in ["state","threshold","duration","ipBlockTime"]:
        if k in body: g["cc"][k] = int(body[k]) if k != "state" else body[k]
    waf_write_json(os.path.join(WAF_CONF, "global.json"), g)
    return {**{"ok": True, "message": "已保存"}, **nginx_reload()}

# ── API: IP 黑/白名单 ─────────────────────────────
def _read_blacklist_file(name):
    """读取 ipBlack/ipWhite.json，兼容 1Panel 对象规则和早期字符串规则。"""
    data = waf_read_json(os.path.join(WAF_RULES, f"{name}.json"))
    if data is None: return []
    rules = data if isinstance(data, list) else data.get("rules", []) if isinstance(data, dict) else []
    return [_normalize_ip_rule(r) for r in rules if _normalize_ip_rule(r)]

def _write_blacklist_file(name, rules):
    """写入 1Panel 原生规则格式: {rules:[{type, ipv4/ipv6/ipGroup/ipStart/ipEnd}]}。"""
    waf_write_json(os.path.join(WAF_RULES, f"{name}.json"), {"rules": rules})

def _normalize_ip_rule(rule):
    if isinstance(rule, str):
        return _make_ip_rule(rule)
    if not isinstance(rule, dict):
        return None
    typ = rule.get("type")
    if typ == "ipv4" and rule.get("ipv4"):
        return _complete_ip_rule({**rule, "type": "ipv4", "ipv4": rule["ipv4"].strip()})
    if typ == "ipv6" and rule.get("ipv6"):
        return _complete_ip_rule({**rule, "type": "ipv6", "ipv6": rule["ipv6"].strip()})
    if typ == "ipArr" and rule.get("ipStart") and rule.get("ipEnd"):
        return _complete_ip_rule({**rule, "type": "ipArr", "ipStart": rule["ipStart"].strip(), "ipEnd": rule["ipEnd"].strip()})
    if typ == "ipGroup" and rule.get("ipGroup"):
        return _complete_ip_rule({**rule, "type": "ipGroup", "ipGroup": rule["ipGroup"].strip()})
    for key in ("ipv4", "ipv6", "ipGroup"):
        if rule.get(key):
            return _make_ip_rule(rule[key])
    return None

def _make_ip_rule(value):
    value = str(value).strip()
    if not value: return None
    if "-" in value:
        start, end = [x.strip() for x in value.split("-", 1)]
        return _complete_ip_rule({"type": "ipArr", "ipStart": start, "ipEnd": end})
    if ":" in value:
        return _complete_ip_rule({"type": "ipv6", "ipv6": value}) if "/" not in value else _complete_ip_rule({"type": "ipGroup", "ipGroup": value})
    if "/" in value:
        return _complete_ip_rule({"type": "ipGroup", "ipGroup": value})
    return _complete_ip_rule({"type": "ipv4", "ipv4": value})

def _complete_ip_rule(rule):
    full = {
        "name": rule.get("name", ""),
        "state": rule.get("state") or "on",
        "type": rule.get("type", "ipv4"),
        "ipv4": rule.get("ipv4", ""),
        "ipv6": rule.get("ipv6", ""),
        "ipStart": rule.get("ipStart", ""),
        "ipEnd": rule.get("ipEnd", ""),
        "ipGroup": rule.get("ipGroup", ""),
        "description": rule.get("description", ""),
    }
    return full

def _ip_rule_value(rule):
    rule = _normalize_ip_rule(rule)
    if not rule: return ""
    if rule["type"] in ("ipv4", "ipv6"): return rule[rule["type"]]
    if rule["type"] == "ipGroup": return rule["ipGroup"]
    if rule["type"] == "ipArr": return f'{rule["ipStart"]}-{rule["ipEnd"]}'
    return ""

def _set_ip_rule_state(name, ip, state):
    data = _read_blacklist_file(name)
    changed = False
    for rule in data:
        if _ip_rule_value(rule) == ip:
            rule["state"] = "on" if state == "on" else "off"
            changed = True
    if changed:
        _write_blacklist_file(name, data)
    return changed

@app.get("/api/blacklist")
async def blacklist_get():
    return {
        "ipBlack": _read_blacklist_file("ipBlack"),
        "ipWhite": _read_blacklist_file("ipWhite"),
    }

@app.post("/api/blacklist_add")
async def blacklist_add(request: Request):
    body = await request.json()
    ip = body["ip"].strip()
    rule = _make_ip_rule(ip)
    if not rule: raise HTTPException(400, "IP 不能为空")
    lst = "ipWhite" if body.get("type") == "white" else "ipBlack"
    data = _read_blacklist_file(lst)
    values = {_ip_rule_value(x) for x in data}
    if _ip_rule_value(rule) not in values:
        data.append(rule); _write_blacklist_file(lst, data)
    return {**{"ok": True, "message": f"已添加 {ip}"}, **nginx_reload()}

@app.post("/api/blacklist_remove")
async def blacklist_remove(request: Request):
    body = await request.json()
    ip = body["ip"].strip()
    lst = "ipWhite" if body.get("type") == "white" else "ipBlack"
    data = [x for x in _read_blacklist_file(lst) if _ip_rule_value(x) != ip]
    _write_blacklist_file(lst, data)
    return {**{"ok": True, "message": f"已移除 {ip}"}, **nginx_reload()}

@app.post("/api/blacklist_state")
async def blacklist_state(request: Request):
    body = await request.json()
    ip = body["ip"].strip()
    state = "on" if body.get("state") == "on" else "off"
    lst = "ipWhite" if body.get("type") == "white" else "ipBlack"
    if not _set_ip_rule_state(lst, ip, state):
        raise HTTPException(404, "规则不存在")
    return {**{"ok": True, "message": "状态已更新"}, **nginx_reload()}

# ── API: ASN 查询 ─────────────────────────────────
@app.get("/api/asn_lookup")
async def asn_lookup(asn: str):
    """根据 ASN 查询 IP 范围（使用 RIPE stat API）"""
    asn_num = asn.strip().upper().replace("AS", "")
    if not asn_num.isdigit(): raise HTTPException(400, "无效的 ASN 格式，例如: AS4134 或 4134")
    try:
        import urllib.request
        # RIPE stat API - 免费、不限速
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}"
        req = urllib.request.Request(url, headers={"User-Agent": "WAF-Panel/1.0"})
        resp = json.loads(urllib.request.urlopen(req, timeout=15).read())
        prefixes = []
        for p in resp.get("data", {}).get("prefixes", []):
            prefixes.append({"prefix": p["prefix"], "description": ""})
        # 获取 ASN 名称
        url2 = f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn_num}"
        req2 = urllib.request.Request(url2, headers={"User-Agent": "WAF-Panel/1.0"})
        try:
            resp2 = json.loads(urllib.request.urlopen(req2, timeout=10).read())
            name = resp2.get("data", {}).get("holder", f"AS{asn_num}")
        except: name = f"AS{asn_num}"
        return {"asn": f"AS{asn_num}", "name": name, "prefixes": prefixes, "count": len(prefixes)}
    except Exception as e:
        raise HTTPException(500, f"ASN 查询失败: {str(e)}")

@app.post("/api/asn_block")
async def asn_block(request: Request):
    """将 ASN 的所有 IP 范围加入黑名单"""
    body = await request.json()
    prefixes = body.get("prefixes", [])
    added = 0
    data = _read_blacklist_file("ipBlack")
    values = {_ip_rule_value(x) for x in data}
    for p in prefixes:
        prefix = p["prefix"] if isinstance(p, dict) else str(p)
        rule = _make_ip_rule(prefix)
        if rule and _ip_rule_value(rule) not in values:
            data.append(rule)
            values.add(_ip_rule_value(rule))
            added += 1
    _write_blacklist_file("ipBlack", data)
    return {**{"ok": True, "message": f"已添加 {added} 个 IP 范围", "added": added}, **nginx_reload()}

# ── API: 拦截页面管理 ─────────────────────────────
@app.get("/api/pages")
async def pages_list():
    pages = []
    for f in os.listdir(WAF_DEFAULT):
        if f.endswith(".html"):
            p = os.path.join(WAF_DEFAULT, f)
            pages.append({"name": f, "size": os.path.getsize(p), "mtime": os.path.getmtime(p)})
    return {"pages": pages}

@app.get("/api/page_get")
async def page_get(name: str):
    path = os.path.join(WAF_DEFAULT, os.path.basename(name))
    if not os.path.exists(path): raise HTTPException(404, "文件不存在")
    with open(path) as f: return {"name": name, "content": f.read()}

@app.post("/api/page_save")
async def page_save(request: Request):
    body = await request.json()
    path = os.path.join(WAF_DEFAULT, os.path.basename(body["name"]))
    if not os.path.exists(path): raise HTTPException(404, "文件不存在")
    with open(path, 'w') as f: f.write(body["content"])
    return {**{"ok": True, "message": "已保存"}, **nginx_reload()}

# ── API: 自动封禁 / fail2ban 联动 ──────────────────
@app.get("/api/autoban_config")
async def autoban_config_get():
    cfg = load_autoban_config()
    status = fail2ban_status(cfg.get("jail_name"))
    return {"config": cfg, "status": status}

@app.post("/api/autoban_config")
async def autoban_config_set(request: Request):
    body = await request.json()
    cfg = apply_autoban_config(body)
    return {"ok": True, "message": "已保存自动封禁配置", "config": cfg}

@app.post("/api/autoban_restart")
async def autoban_restart():
    return restart_fail2ban()

@app.get("/api/autoban_status")
async def autoban_status():
    cfg = load_autoban_config()
    return fail2ban_status(cfg.get("jail_name"))

@app.post("/api/autoban_ban")
async def autoban_ban(request: Request):
    body = await request.json()
    ip = body.get("ip", "").strip()
    if not ip: raise HTTPException(400, "IP 不能为空")
    cfg = load_autoban_config()
    jail = cfg.get("jail_name", "waf-panel-autoban")
    out = subprocess.run(["fail2ban-client", "set", jail, "banip", ip], capture_output=True, text=True)
    return {"ok": out.returncode == 0, "output": (out.stdout + out.stderr).strip()}

@app.post("/api/autoban_unban")
async def autoban_unban(request: Request):
    body = await request.json()
    ip = body.get("ip", "").strip()
    if not ip: raise HTTPException(400, "IP 不能为空")
    cfg = load_autoban_config()
    jail = cfg.get("jail_name", "waf-panel-autoban")
    out = subprocess.run(["fail2ban-client", "set", jail, "unbanip", ip], capture_output=True, text=True)
    return {"ok": out.returncode == 0, "output": (out.stdout + out.stderr).strip()}

# ── API: Nginx 重载 ───────────────────────────────
@app.post("/api/reload")
async def reload():
    return nginx_reload()
