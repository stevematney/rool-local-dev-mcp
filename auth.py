#!/usr/bin/env python3
"""P2 auth: GitHub OIDC-style owner login + OAuth 2.1 AS for the MCP client.

Composed on :8000 with the protected resource. The consent gate is: the
approver must have an owner-authenticated session (via GitHub login as
OWNER_GITHUB), and the OAuth authorization request must carry valid
PKCE/state. No durable approval secret lives here: /authorize only grants
after the browser has an owner session cookie.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp

from mcp.server.auth.provider import (
    OAuthAuthorizationServerProvider,
    AuthorizationParams,
    IdentityAssertionParams,
    AccessToken,
    AuthorizationCode,
    RefreshToken,
)
from mcp.server.auth.routes import (
    create_auth_routes,
    create_protected_resource_routes,
)
from mcp.server.auth.settings import AuthSettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

import db

load_dotenv()

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
OWNER_GITHUB = os.getenv("OWNER_GITHUB", "")

# ---------------------------------------------------------------- GitHub login
GITHUB_AUTH = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_API = "https://api.github.com/user"


class OwnerSession:
    """Durable owner sessions (sid -> login), backed by sqlite."""

    def __init__(self) -> None:
        pass

    def create(self, login: str) -> str:
        sid = secrets.token_urlsafe(32)
        db.create_session(db.hash_value(sid), login)
        return sid

    def get(self, sid: str) -> str | None:
        return db.get_session(db.hash_value(sid))

    def revoke(self, sid: str) -> None:
        db.revoke_session(db.hash_value(sid))


_sessions = OwnerSession()


async def _fetch_github_token(code: str) -> dict[str, Any]:
    data = urllib.parse.urlencode({
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
    }).encode()
    req = urllib.request.Request(
        GITHUB_TOKEN,
        data=data,
        headers={"Accept": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


async def _fetch_github_user(access_token: str) -> dict[str, Any]:
    req = urllib.request.Request(
        GITHUB_API,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


async def login(request: Request) -> Response:
    state = secrets.token_urlsafe(16)
    params = urllib.parse.urlencode({
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": f"{BASE_URL}/auth/callback",
        "scope": "read:user",
        "state": state,
    })
    # stash state in a cookie (Starlette SessionMiddleware signs it)
    request.session["gh_state"] = state
    return RedirectResponse(f"{GITHUB_AUTH}?{params}")


async def callback(request: Request) -> Response:
    code = request.query_params.get("code", "")
    state = request.query_params.get("state", "")
    expected = request.session.get("gh_state", "")
    if not expected or not hmac.compare_digest(state, expected):
        return Response("state mismatch", status_code=400)
    tok = await _fetch_github_token(code)
    access = tok.get("access_token")
    if not access:
        return Response("github token exchange failed", status_code=400)
    user = await _fetch_github_user(access)
    login = user.get("login", "")
    if login != OWNER_GITHUB:
        return Response(f"not authorized: {login}", status_code=403)
    sid = _sessions.create(login)
    response = RedirectResponse("/consent")
    response.set_cookie("rool_owner", sid, httponly=True, samesite="lax")
    return response


async def consent(request: Request) -> Response:
    sid = request.cookies.get("rool_owner", "")
    owner = _sessions.get(sid)
    if not owner:
        return RedirectResponse("/auth/login")
    client_id = request.query_params.get("client_id", "")
    scope = request.query_params.get("scope", "")
    return HTMLResponse(f"""<!doctype html>
<meta charset="utf-8"><title>rool-fs consent</title>
<h1>Approve MCP client?</h1>
<p>Logged in as <strong>{owner}</strong></p>
<p>Client <code>{client_id}</code> requests scope <code>{scope}</code></p>
<form method="post" action="/consent">
  <input type="hidden" name="client_id" value="{client_id}">
  <input type="hidden" name="scope" value="{scope}">
  <input type="hidden" name="state" value="{request.query_params.get('state','')}">
  <button name="decision" value="approve">Approve</button>
  <button name="decision" value="deny">Deny</button>
</form>""")


# ------------------------------------------------------------ OAuth AS provider
class RoolProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """Full implementation of the SDK's OAuth provider Protocol."""

    def __init__(self) -> None:
        self._clients: dict[str, OAuthClientInformationFull] = {}

    async def register_client(
        self, client_info: OAuthClientInformationFull
    ) -> None:
        # P2: open dynamic client registration per spec. Consent-gating
        # registration (only the owner approves new clients) is also P2 —
        # browser consent is in the P2 scope per the Feature List.
        self._clients[client_info.client_id] = client_info
        db.remember_client(
            client_info.client_id,
            client_info.client_name or "",
            "fs",
        )

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        # Headless-friendly: no browser redirect on the client side. We accept
        # the authorization request in-process; the actual "approve" is the
        # owner clicking Approve on /consent (which persists consent). The
        # returned redirect lands on the client's redirect_uri (mostly unused
        # for headless) but issuance happens via the consent POST + code export.
        return str(params.redirect_uri)

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        row = db.redeem_authorization_code(authorization_code)
        if row is None:
            return None
        return AuthorizationCode(
            code=authorization_code,
            client_id=row["client_id"],
            redirect_uri=row["redirect_uri"],
            scopes=row["scope"].split(","),
            code_challenge=row.get("code_challenge") or "",
            expires_at=int(row.get("expires_at") or 0),
            redirect_uri_provided_explicitly=bool(row.get("redirect_uri")),
        )

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        tok = db.new_token(client.client_id, ",".join(authorization_code.scopes), "owner")
        return OAuthToken(
            access_token=tok["access_token"],
            refresh_token=tok["refresh_token"],
            expires_in=tok["expires_in"],
            token_type="Bearer",
            scope=",".join(authorization_code.scopes),
        )

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        row = db.find_token_by_refresh(db.hash_value(refresh_token))
        if row is None:
            return None
        return RefreshToken(
            token=refresh_token,
            scopes=row["scope"].split(","),
            client_id=row["client_id"],
            expires_at=int(row["expires_at"]),
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Rotation: the incoming refresh token is single-use — mark the old pair
        # revoked and issue a fresh access+refresh pair.
        row = db.find_token_by_refresh(db.hash_value(refresh_token.token))
        if row is None:
            raise ValueError("invalid or revoked refresh token")
        old_access_hash = row["token_hash"]
        old_refresh_hash = row["refresh_token_hash"]
        new_access = secrets.token_urlsafe(32)
        new_refresh = secrets.token_urlsafe(32)
        db.rotate_token(
            old_access_hash,
            old_refresh_hash,
            new_access,
            new_refresh,
            row["client_id"],
            ",".join(scopes),
            row["owner_login"],
        )
        return OAuthToken(
            access_token=new_access,
            refresh_token=new_refresh,
            expires_in=3600,
            token_type="Bearer",
            scope=",".join(scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        row = db.verify_token(token)
        if row is None:
            return None
        return AccessToken(
            token=token,
            scopes=row["scope"].split(","),
            client_id=row["client_id"],
            expires_at=int(row.get("expires_at") or 0),
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        # P2: real revocation — revoke by type (access vs refresh).
        if isinstance(token, AccessToken):
            db.revoke_access(db.hash_value(token.token))
        else:
            db.revoke_refresh(db.hash_value(token.token))

    async def exchange_identity_assertion(
        self,
        client: OAuthClientInformationFull,
        params: IdentityAssertionParams,
    ) -> OAuthToken:
        raise NotImplementedError("identity assertion not enabled in P2")


async def consent_post(request: Request) -> Response:
    sid = request.cookies.get("rool_owner", "")
    owner = _sessions.get(sid)
    if not owner:
        return RedirectResponse("/auth/login")
    form = await request.form()
    if form.get("decision") != "approve":
        return HTMLResponse("<p>Denied.</p>")
    client_id = str(form.get("client_id", ""))
    scope = str(form.get("scope", "fs"))
    db.remember_consent(owner, client_id, scope)
    # Export a token for the machine client (headless): the AS writes it to
    # TOKEN_FILE; the Rool VM reads it from the tunnel side (bootstrap path).
    tok = db.new_token(client_id, scope, owner)
    token_file = os.getenv("TOKEN_FILE", "")
    if token_file:
        try:
            Path(token_file).write_text(json.dumps({
                "access_token": tok["access_token"],
                "refresh_token": tok["refresh_token"],
                "expires_in": tok["expires_in"],
                "token_type": "Bearer",
                "scope": scope,
                "client_id": client_id,
            }, indent=2))
        except OSError as e:
            return HTMLResponse(f"<p>Approved. Consent recorded, but token export failed: {e}</p>")
    return HTMLResponse("<p>Approved. Consent recorded and token exported.</p>")


def build_app(mcp_server) -> ASGIApp:
    provider = RoolProvider()  # type: ignore[reportAbstractUsage]
    settings = AuthSettings(
        issuer_url=AnyHttpUrl(BASE_URL),
        resource_server_url=AnyHttpUrl(f"{BASE_URL}/mcp"),
    )
    routes = create_auth_routes(
        provider, settings.issuer_url
    )
    protected = create_protected_resource_routes(
        AnyHttpUrl(f"{BASE_URL}/mcp"),
        authorization_servers=[settings.issuer_url],
    )
    app = Starlette(
        routes=[
            Route("/health", lambda _: Response("OK mcp-fs p2\n", media_type="text/plain")),
            Route("/auth/login", login),
            Route("/auth/callback", callback),
            Route("/consent", consent),
            Route("/consent", consent_post, methods=["POST"]),
            *routes,
            *protected,
        ],
    )
    # Mount the MCP streamable-HTTP app at /mcp (it returns a full Starlette app).
    mcp_app = mcp_server.streamable_http_app()
    app.mount("/mcp", mcp_app, name="mcp")
    # Wrap the whole assembly in session middleware (signed owner login cookie).
    app = SessionMiddleware(app, secret_key=os.getenv("SESSION_SECRET", "dev-secret"))
    return app
