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
import csv
import glob as stdglob
import os
import re
from pathlib import Path


from dotenv import load_dotenv
from mcp.server import MCPServer
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import AnyHttpUrl
load_dotenv()

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000").rstrip("/")


def _env_list(name: str) -> list[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return []
    return [item.strip() for row in csv.reader([raw]) for item in row if item.strip()]


from deny_list import (SENSITIVE_FILES as sensitive_file_defaults,
                       DENIED_FOLDERS as denied_folder_defaults,
                       READ_ONLY_FOLDERS as read_only_folder_defaults)

SENSITIVE_FILES = _env_list("SENSITIVE_FILES") + sensitive_file_defaults
DENIED_FOLDERS = _env_list("DENIED_FOLDERS") + denied_folder_defaults
READ_ONLY_FOLDERS = _env_list("READ_ONLY_FOLDERS") + read_only_folder_defaults
DENY_ALL = SENSITIVE_FILES + DENIED_FOLDERS
DENY_WRITE = READ_ONLY_FOLDERS


def _deny_regexes(patterns: list[str]) -> list[re.Pattern[str]]:
    out: list[re.Pattern[str]] = []
    for pattern in patterns:
        out.append(re.compile(stdglob.translate(
            pattern, recursive=True, include_hidden=True)))
        if not stdglob.has_magic(pattern):
            out.append(re.compile(stdglob.translate(
                f"{pattern}/**", recursive=True, include_hidden=True)))
    return out


DENY_ALL_REGEXES = _deny_regexes(DENY_ALL)
DENY_WRITE_REGEXES = _deny_regexes(DENY_ALL + DENY_WRITE)


def _path_allowed(path: str, *, write: bool = False) -> bool:
    regexes = DENY_WRITE_REGEXES if write else DENY_ALL_REGEXES
    return not any(regex.match(path) for regex in regexes)


def _abs(p: str | Path) -> Path:
    return (SANDBOX_ROOT / p).resolve()


def _rel(p: str | Path) -> str:
    return Path(p).resolve().relative_to(SANDBOX_ROOT).as_posix()


def _is_safe(p: str | Path, *, write: bool = False) -> bool:
    candidate = _abs(p)
    if not candidate.is_relative_to(SANDBOX_ROOT):
        return False
    if not _path_allowed(_rel(candidate), write=write):
        return False
    if write:
        return all(_path_allowed(parent.as_posix(), write=True)
                   for parent in Path(_rel(candidate)).parents
                   if parent.as_posix() != ".")
    return True

from auth import RoolProvider  # noqa: E402

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


@server.tool()
async def list_dir(path: str) -> str:
    """List a directory under the project sandbox."""
    if not _is_safe(path):
        raise ToolError(f"access denied: {path}")
    p = _abs(path)
    if not p.is_dir():
        raise FileNotFoundError(str(p))
    return "\n".join(sorted(_rel(x) for x in p.iterdir()
                             if x.is_file() and _is_safe(x)))


@server.tool()
async def read_file(path: str) -> str:
    """Read a file under the project sandbox."""
    if not _is_safe(path):
        raise ToolError(f"access denied: {path}")
    p = _abs(path)
    if not p.is_file():
        raise FileNotFoundError(str(p))
    return p.read_text(errors="replace")


@server.tool()
async def write_file(path: str, content: str) -> str:
    """Write a file under the project sandbox (create/overwrite)."""
    if not _is_safe(path, write=True):
        raise ToolError(f"access denied: {path}")
    p = _abs(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return f"wrote {_rel(p)}"


@server.tool()
async def search_dir(pattern: str, path: str = ".") -> str:
    """Regex search under the project sandbox."""
    if not _is_safe(path):
        raise ToolError(f"access denied: {path}")
    pat = re.compile(pattern)
    hits = [_rel(f) for f in _abs(path).rglob("*")
            if f.is_file() and _is_safe(f)
            and pat.search(f.read_text(errors="replace"))]
    return "\n".join(sorted(hits)) or "(no matches)"


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
