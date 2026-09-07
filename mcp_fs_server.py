#!/usr/bin/env python3
"""
mcp_fs_server.py — rool-fs MCP server with OAuth 2.1 (P2).

Shapes:
  - :8000 (tunnel-exposed)  AS + protected resource: /mcp, /health,
                            /.well-known/oauth-authorization-server, /authorize,
                            /token, /register, /revoke, /auth/login, /auth/callback
  - owner consent via GitHub OIDC-style login, then approve/deny

Run:  python3 mcp_fs_server.py            (from this directory)
"""
from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path

from dotenv import load_dotenv
from mcp.server import MCPServer
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from pydantic import AnyHttpUrl

load_dotenv()

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000").rstrip("/")


# The provider doubles as the token verifier: the SDK wraps /mcp with
# BearerAuthBackend + RequireAuthMiddleware using auth_server_provider.
# Instantiated once here so MCPServer construction has it; auth.build_app
# reuses the same provider for the outer AS routes.
from auth import RoolProvider  # noqa: E402  (after load_dotenv)

auth_provider = RoolProvider()

PORT = int(os.getenv("PORT", "8000"))
BIND_HOST = os.getenv("BIND_HOST", "::")
SANDBOX_ROOT = Path(os.getenv("SANDBOX_ROOT", Path(
    __file__).resolve().parent)).resolve()

server = MCPServer(
    name="rool-fs",
    title="rool-fs project filesystem",
    instructions="Sandboxed read/write tools scoped to the project folder.",
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(BASE_URL),
        resource_server_url=AnyHttpUrl(f"{BASE_URL}/mcp"),
        required_scopes=["fs"],
        client_registration_options=ClientRegistrationOptions(enabled=True),
    ),
    auth_server_provider=auth_provider,
)


def _abs(p: str) -> Path:
    """Resolve inside SANDBOX_ROOT; escape or deny-list hit -> PermissionError."""
    root = SANDBOX_ROOT.resolve()
    candidate = (root / p).resolve()
    if not candidate.is_relative_to(root):
        raise PermissionError(f"escape attempt blocked: {p}")
    _check_blocklist(candidate, p)
    return candidate


# Central deny-list: any path matching these patterns is inaccessible to
# every tool op (read, write, list, search). Enforced in _abs() and
# search_dir(); symlink resolution happens before matching (candidate is
# already resolved), so links pointing at blocked files are caught too.
BLOCKLIST_PATTERNS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    ".git",
    "rool_fs.db",
)


def _is_blocked(candidate: Path) -> bool:
    rel = candidate.relative_to(SANDBOX_ROOT)
    parts = rel.parts
    for pat in BLOCKLIST_PATTERNS:
        if "*" in pat:
            if rel.match(pat):
                return True
        elif pat in parts:  # file or directory component (e.g. .git/ anything)
            return True
    return False


def _check_blocklist(candidate: Path, raw: str) -> None:
    if _is_blocked(candidate):
        raise PermissionError(f"blocked by deny-list: {raw}")


@server.tool()
async def list_dir(path: str) -> str:
    """List a directory under the project sandbox."""
    p = _abs(path)
    if not p.is_dir():
        raise FileNotFoundError(str(p))
    return "\n".join(sorted(x.name for x in p.iterdir()))


@server.tool()
async def read_file(path: str) -> str:
    """Read a file under the project sandbox."""
    return _abs(path).read_text(errors="replace")


@server.tool()
async def write_file(path: str, content: str) -> str:
    """Write a file under the project sandbox (create/overwrite)."""
    p = _abs(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return f"wrote {p.relative_to(SANDBOX_ROOT)}"


@server.tool()
async def search_dir(pattern: str, path: str = ".") -> str:
    """Regex search under the project sandbox."""
    root = SANDBOX_ROOT.resolve()
    pat = re.compile(pattern)
    hits = []
    for f in root.joinpath(path).rglob("*"):
        if f.is_file():
            if f.is_symlink():
                f = f.resolve()
                if not f.is_relative_to(root) or _is_blocked(f):
                    continue
            elif _is_blocked(f):
                continue
            try:
                txt = f.read_text(errors="replace")
            except Exception:
                continue
            if pat.search(txt):
                hits.append(f.relative_to(root).as_posix())
    if not hits:
        return "(no matches)"
    return "\n".join(sorted(hits))


from auth import build_app  # noqa: E402  (after tools are registered)


async def main() -> None:
    app = build_app(server)
    print(f"rool-fs P2 on {BIND_HOST}:{PORT}  sandbox={SANDBOX_ROOT}")
    import uvicorn
    config = uvicorn.Config(app, host=BIND_HOST,
                            port=PORT, log_level="info",
                            access_log=True)
    await uvicorn.Server(config).serve()


if __name__ == "__main__":
    asyncio.run(main())
