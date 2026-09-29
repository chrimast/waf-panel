from __future__ import annotations

import os
import secrets
from pathlib import Path


def _panel_home() -> Path:
    return Path(os.environ.get("WAF_PANEL_HOME") or Path(__file__).resolve().parent)


PASSWORD_STORE = _panel_home() / "data" / "panel-password"


def _store_path() -> Path:
    return Path(PASSWORD_STORE)


def _env_password() -> str:
    return os.environ.get("WAF_PANEL_PASSWORD", "") or ""


def current_password() -> str:
    path = _store_path()
    if path.exists():
        value = path.read_text().strip()
        if value:
            return value
    return _env_password()


def verify_password(password: str) -> bool:
    expected = current_password()
    offered = password or ""
    if not expected:
        return False
    return secrets.compare_digest(offered, expected)


def change_password(current: str, new_password: str) -> None:
    new_password = (new_password or "").strip()
    if not verify_password(current or ""):
        raise ValueError("当前密码不正确")
    if len(new_password) < 8:
        raise ValueError("新密码至少 8 位")
    if new_password == current_password():
        raise ValueError("新密码不能与当前密码相同")
    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(new_password + "\n")
    path.chmod(0o600)
