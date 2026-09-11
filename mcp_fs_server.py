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
import glob
import os
import re
from pathlib import Path

from dotenv import load_dotenv
from mcp.server import MCPServer
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import AnyHttpUrl
from deny_list import DENY_LIST

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

DENY_REGEXES = [re.compile(glob.translate(
    p, recursive=True, include_hidden=True)) for p in DENY_LIST]


def _path_allowed(path: str) -> bool:
    return not any(r.match(path) for r in DENY_REGEXES)


def _abs(p: str) -> Path:
    """Resolve inside SANDBOX_ROOT; escape -> PermissionError."""
    root = SANDBOX_ROOT.resolve()
    candidate = (root / p).resolve()
    if not candidate.is_relative_to(root):
        raise PermissionError(f"escape attempt blocked: {p}")
    return candidate


@server.tool()
async def list_dir(path: str) -> str:
    """List a directory under the project sandbox."""
    p = _abs(path)
    if not p.is_dir():
        raise FileNotFoundError(str(p))
    return "\n".join(sorted(x.name for x in p.iterdir() if _path_allowed(x.relative_to(SANDBOX_ROOT).as_posix())))


@server.tool()
async def read_file(path: str) -> str:
    """Read a file under the project sandbox."""
    abs_path = _abs(path)
    if not abs_path.is_file():
        raise FileNotFoundError(str(abs_path))
    if not _path_allowed(abs_path.relative_to(SANDBOX_ROOT).as_posix()):
        raise ToolError(f"access denied: {path}")
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
