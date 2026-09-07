#!/usr/bin/env python3
"""Durable sqlite stores for the P2 auth server."""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from typing import Any
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "rool_fs.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                client_secret_hash TEXT,
                client_name TEXT,
                redirect_uris TEXT,
                scopes TEXT,
                created_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS auth_codes (
                code_hash TEXT PRIMARY KEY,
                client_id TEXT,
                redirect_uri TEXT,
                scope TEXT,
                owner_login TEXT,
                code_challenge TEXT,
                state TEXT,
                expires_at INTEGER,
                used INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS tokens (
                token_hash TEXT PRIMARY KEY,
                client_id TEXT,
                scope TEXT,
                owner_login TEXT,
                expires_at INTEGER,
                refresh_token_hash TEXT,
                revoked INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS consent (
                client_id TEXT,
                owner_login TEXT,
                scope TEXT,
                granted_at INTEGER,
                PRIMARY KEY (client_id, owner_login, scope)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                sid_hash TEXT PRIMARY KEY,
                login TEXT,
                created_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS device_codes (
                device_code_hash TEXT PRIMARY KEY,
                user_code TEXT,
                client_id TEXT,
                scope TEXT,
                status TEXT,
                created_at INTEGER,
                approved_at INTEGER
            );
            """
        )
        # Lightweight migration: older dbs created before the `revoked` column
        # won't have it (CREATE TABLE IF NOT EXISTS is a no-op on existing dbs).
        cols = {row[1] for row in conn.execute("PRAGMA table_info(tokens)").fetchall()}
        if "revoked" not in cols:
            conn.execute("ALTER TABLE tokens ADD COLUMN revoked INTEGER DEFAULT 0")


def hash_value(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


def remember_client(client_id: str, client_name: str, scopes: str, client_secret: str | None = None) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO clients (client_id, client_secret_hash, client_name, redirect_uris, scopes, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (client_id, hash_value(client_secret) if client_secret else None, client_name,
             "", scopes, int(time.time())),
        )


def remember_consent(owner_login: str, client_id: str, scope: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO consent (client_id, owner_login, scope, granted_at) VALUES (?,?,?,?)",
            (client_id, owner_login, scope, int(time.time())),
        )


def create_session(sid_hash: str, login: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sessions (sid_hash, login, created_at) VALUES (?,?,?)",
            (sid_hash, login, int(time.time())),
        )


def get_session(sid_hash: str) -> str | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT login FROM sessions WHERE sid_hash = ?", (sid_hash,)
        ).fetchone()
    return row[0] if row else None


def revoke_session(sid_hash: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE sid_hash = ?", (sid_hash,))


def new_authorization_code(client_id: str, redirect_uri: str, scope: str, owner_login: str,
                           code_challenge: str, state: str) -> str:
    code = secrets.token_urlsafe(32)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO auth_codes (code_hash, client_id, redirect_uri, scope, owner_login, code_challenge, state, expires_at, used) "
            "VALUES (?,?,?,?,?,?,?,?,0)",
            (hash_value(code), client_id, redirect_uri, scope, owner_login,
             code_challenge, state, int(time.time()) + 600),
        )
    return code


def redeem_authorization_code(code: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM auth_codes WHERE code_hash=? AND used=0 AND expires_at>?",
            (hash_value(code), int(time.time())),
        ).fetchone()
        if row is None:
            return None
        conn.execute("UPDATE auth_codes SET used=1 WHERE code_hash=?", (hash_value(code),))
        return dict(row)


def new_token(client_id: str, scope: str, owner_login: str) -> dict[str, Any]:
    access = secrets.token_urlsafe(32)
    refresh = secrets.token_urlsafe(32)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO tokens (token_hash, client_id, scope, owner_login, expires_at, refresh_token_hash) "
            "VALUES (?,?,?,?,?,?)",
            (hash_value(access), client_id, scope, owner_login, int(time.time()) + 3600,
             hash_value(refresh)),
        )
    return {"access_token": access, "refresh_token": refresh, "expires_in": 3600}


def verify_token(access_token: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM tokens WHERE token_hash=? AND expires_at>? AND revoked=0",
            (hash_value(access_token), int(time.time())),
        ).fetchone()
        return dict(row) if row else None


def find_token_by_refresh(refresh_token_hash: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM tokens WHERE refresh_token_hash=? AND revoked=0 LIMIT 1",
            (refresh_token_hash,),
        ).fetchone()
    return dict(row) if row else None


def rotate_token(
    old_access_hash: str,
    old_refresh_hash: str,
    new_access: str,
    new_refresh: str,
    client_id: str,
    scope: str,
    owner_login: str,
) -> dict[str, Any]:
    """Mark the old pair revoked and insert the new pair (rotation)."""
    now = int(time.time())
    with _connect() as conn:
        conn.execute(
            "UPDATE tokens SET revoked = 1 WHERE token_hash = ? OR refresh_token_hash = ?",
            (old_access_hash, old_refresh_hash),
        )
        conn.execute(
            "INSERT INTO tokens (token_hash, client_id, scope, owner_login, expires_at, refresh_token_hash, revoked) "
            "VALUES (?,?,?,?,?,?,0)",
            (
                hash_value(new_access),
                client_id,
                scope,
                owner_login,
                now + 3600,
                hash_value(new_refresh),
            ),
        )
    return {"access_token": new_access, "refresh_token": new_refresh, "expires_in": 3600}


def revoke_access(access_hash: str) -> None:
    with _connect() as conn:
        conn.execute("UPDATE tokens SET revoked = 1 WHERE token_hash = ?", (access_hash,))


def revoke_refresh(refresh_hash: str) -> None:
    with _connect() as conn:
        conn.execute("UPDATE tokens SET revoked = 1 WHERE refresh_token_hash = ?", (refresh_hash,))


def is_token_revoked(access_hash: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT revoked FROM tokens WHERE token_hash = ? LIMIT 1", (access_hash,)
        ).fetchone()
    return bool(row and row[0])


def new_device_code(client_id: str, scope: str) -> dict[str, str]:
    """Issue a device/user code pair for the device authorization grant."""
    device_code = secrets.token_urlsafe(32)
    user_code = "-".join(
        "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(4))
        for _ in range(2)
    )
    with _connect() as conn:
        conn.execute(
            "INSERT INTO device_codes (device_code_hash, user_code, client_id, scope, status, created_at) VALUES (?,?,?,?,?,?)",
            (hash_value(device_code), user_code, client_id, scope, "pending", int(time.time())),
        )
    return {"device_code": device_code, "user_code": user_code}


def find_device_by_user_code(user_code: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT device_code_hash, client_id, scope, status FROM device_codes WHERE user_code = ? AND status = 'pending'",
            (user_code.upper(),),
        ).fetchone()
    if not row:
        return None
    return {
        "device_code_hash": row[0], "client_id": row[1],
        "scope": row[2], "status": row[3],
    }


def approve_device(device_code_hash: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE device_codes SET status = 'approved', approved_at = ? WHERE device_code_hash = ?",
            (int(time.time()), device_code_hash),
        )


def consume_device_code(device_code_hash: str) -> dict[str, Any] | None:
    """Atomically mark an approved device code as consumed, returning its grant info."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT client_id, scope, status FROM device_codes WHERE device_code_hash = ?",
            (device_code_hash,),
        ).fetchone()
        if not row or row[2] != "approved":
            return None
        conn.execute("DELETE FROM device_codes WHERE device_code_hash = ?", (device_code_hash,))
    return {"client_id": row[0], "scope": row[1]}


def revoke_device(device_code_hash: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM device_codes WHERE device_code_hash = ?", (device_code_hash,))


def find_device_by_hash(device_code_hash: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT device_code_hash, user_code, client_id, scope, status FROM device_codes WHERE device_code_hash = ?",
            (device_code_hash,),
        ).fetchone()
    if not row:
        return None
    return {
        "device_code_hash": row[0], "user_code": row[1], "client_id": row[2],
        "scope": row[3], "status": row[4],
    }


def get_client(client_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT client_id, client_name, redirect_uris, scopes FROM clients WHERE client_id = ?",
            (client_id,),
        ).fetchone()
    if not row:
        return None
    return {
        "client_id": row[0], "client_name": row[1],
        "redirect_uris": row[2], "scopes": row[3],
    }


def get_last_consent_owner(client_id: str) -> str | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT owner_login FROM consent WHERE client_id = ? ORDER BY granted_at DESC LIMIT 1",
            (client_id,),
        ).fetchone()
    return row[0] if row else None


init()
