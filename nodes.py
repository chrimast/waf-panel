from __future__ import annotations

import json
import os
import secrets
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit


class LocalNodeError(RuntimeError):
    pass


def _panel_home() -> Path:
    return Path(os.environ.get("WAF_PANEL_HOME") or Path(__file__).resolve().parent)


NODES_STORE = _panel_home() / "data" / "nodes.json"


def _store_path() -> Path:
    return Path(NODES_STORE)


def _public_node(node: dict, probe: dict | None = None) -> dict:
    kind = node.get("kind") or "remote"
    if probe is None:
        if kind == "local":
            probe = {"online": True, "status": "online", "message": "本机直连"}
        else:
            probe = {"online": False, "status": "unknown", "message": "尚未检测"}
    return {
        "id": node["id"],
        "name": node.get("name") or node["id"],
        "kind": kind,
        "url": node.get("url") or "",
        "online": bool(probe.get("online")),
        "status": probe.get("status") or ("online" if probe.get("online") else "offline"),
        "message": probe.get("message") or "",
    }


def _default_local_token() -> str:
    explicit = os.environ.get("WAF_AGENT_TOKEN", "").strip()
    if explicit:
        return explicit
    return secrets.token_urlsafe(24)


def _empty_state() -> dict:
    token = _default_local_token()
    return {
        "current_id": "local",
        "nodes": [
            {
                "id": "local",
                "name": "本机",
                "kind": "local",
                "url": "",
                "token": token,
                "online": True,
            }
        ],
    }


def load_state() -> dict:
    path = _store_path()
    if not path.exists():
        state = _empty_state()
        save_state(state)
        return state
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        data = _empty_state()
        save_state(data)
        return data
    nodes = data.get("nodes") or []
    if not any(node.get("id") == "local" for node in nodes):
        local = _empty_state()["nodes"][0]
        nodes.insert(0, local)
        data["nodes"] = nodes
    if not data.get("current_id"):
        data["current_id"] = "local"
    return data


def save_state(state: dict) -> None:
    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2))


def probe_node(node: dict) -> dict:
    if (node or {}).get("kind") == "local" or (node or {}).get("id") == "local":
        return {"online": True, "status": "online", "message": "本机直连"}
    url = agent_api_url(node.get("url") or "", "/agent/health")
    headers = {"Authorization": f"Bearer {node.get('token') or ''}"}
    response = http_request("GET", url, headers=headers, timeout=4)
    body = response.json() if hasattr(response, "json") else {}
    if not isinstance(body, dict):
        body = {}
    if response.status_code == 200 and body.get("ok"):
        return {"online": True, "status": "online", "message": "连接正常"}
    if response.status_code in (401, 403):
        return {"online": False, "status": "auth", "message": "Token 无效"}
    detail = str(body.get("message") or body.get("detail") or f"HTTP {response.status_code}")
    return {"online": False, "status": "offline", "message": detail[:120]}


def list_nodes() -> list[dict]:
    return [_public_node(node, probe_node(node)) for node in load_state()["nodes"]]


def get_node(node_id: str) -> dict | None:
    for node in load_state()["nodes"]:
        if node.get("id") == node_id:
            return dict(node)
    return None


def current_node_id() -> str:
    return load_state().get("current_id") or "local"


def current_node() -> dict:
    node = get_node(current_node_id()) or get_node("local")
    return node or _empty_state()["nodes"][0]


def select_node(node_id: str) -> dict:
    state = load_state()
    if not any(node.get("id") == node_id for node in state["nodes"]):
        raise KeyError(node_id)
    state["current_id"] = node_id
    save_state(state)
    node = get_node(node_id) or {"id": node_id, "name": node_id, "kind": "remote", "url": ""}
    return _public_node(node, probe_node(node))


def add_node(name: str, url: str, token: str) -> dict:
    name = (name or "").strip() or "远程节点"
    url = (url or "").strip().rstrip("/")
    token = (token or "").strip()
    if not url:
        raise ValueError("远程节点地址不能为空")
    if not token:
        raise ValueError("远程节点 Token 不能为空")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("远程节点地址无效")
    url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))
    state = load_state()
    node = {
        "id": "n_" + secrets.token_hex(4),
        "name": name,
        "kind": "remote",
        "url": url,
        "token": token,
        "online": False,
    }
    state["nodes"].append(node)
    save_state(state)
    return _public_node(node, probe_node(node))


def delete_node(node_id: str) -> None:
    if node_id == "local":
        raise ValueError("不能删除本机节点")
    state = load_state()
    state["nodes"] = [node for node in state["nodes"] if node.get("id") != node_id]
    if state.get("current_id") == node_id:
        state["current_id"] = "local"
    save_state(state)


def verify_agent_token(token: str) -> bool:
    offered = (token or "").strip()
    if not offered:
        return False
    explicit = os.environ.get("WAF_AGENT_TOKEN", "").strip()
    if explicit and secrets.compare_digest(offered, explicit):
        return True
    local = get_node("local") or {}
    stored = str(local.get("token") or "")
    return bool(stored) and secrets.compare_digest(offered, stored)


def bearer_from_request(authorization: str | None) -> str:
    value = (authorization or "").strip()
    if value.lower().startswith("bearer "):
        return value.split(" ", 1)[1].strip()
    return ""


def agent_api_url(base_url: str, path: str) -> str:
    base = (base_url or "").rstrip("/") + "/"
    api_path = path if path.startswith("/") else "/" + path
    if api_path.startswith("/agent/"):
        return urljoin(base, api_path.lstrip("/"))
    if api_path.startswith("/api/"):
        return urljoin(base, "agent" + api_path)
    return urljoin(base, "agent/api" + api_path)


def http_request(method: str, url: str, headers=None, payload=None, timeout=None):
    body = None
    req_headers = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload).encode()
        req_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(url, data=body, headers=req_headers, method=method)

    class _Response:
        def __init__(self, status_code: int, data):
            self.status_code = status_code
            self._payload = data

        def json(self):
            return self._payload

    try:
        with urllib.request.urlopen(request, timeout=timeout or 20) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {"raw": raw}
            return _Response(resp.status, parsed)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(raw) if raw else {"error": True, "message": str(exc)}
        except json.JSONDecodeError:
            parsed = {"error": True, "message": raw or str(exc)}
        return _Response(exc.code, parsed)
    except Exception as exc:
        return _Response(502, {"error": True, "message": str(exc)})


def forward_agent_request(node: dict, method: str, path: str, body=None):
    if (node or {}).get("kind") == "local" or (node or {}).get("id") == "local":
        raise LocalNodeError("本机节点不转发")
    url = agent_api_url(node.get("url") or "", path)
    headers = {"Authorization": f"Bearer {node.get('token') or ''}"}
    response = http_request(method, url, headers=headers, payload=body, timeout=20)
    return response.json(), response.status_code
