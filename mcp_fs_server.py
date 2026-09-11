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
import os
import re
from pathlib import Path

from wcmatch import glob as wcglob

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
DENY_READ = SENSITIVE_FILES + DENIED_FOLDERS
DENY_WRITE = READ_ONLY_FOLDERS


def _deny_regexes(patterns: list[str], folders: list[str]) -> list[re.Pattern[str]]:
    out: list[re.Pattern[str]] = []
    for pattern in patterns:
        translated = wcglob.translate(
            pattern, flags=wcglob.GLOBSTAR | wcglob.DOTGLOB)[0]
        out += [re.compile(t) for t in translated]
        if pattern in folders:
            beneath = wcglob.translate(
                f"{pattern}/**", flags=wcglob.GLOBSTAR | wcglob.DOTGLOB)[0]
            out += [re.compile(t) for t in beneath]
    return out


DENY_READ_REGEXES = _deny_regexes(DENY_READ, DENIED_FOLDERS)
DENY_WRITE_REGEXES = _deny_regexes(DENY_READ + DENY_WRITE, DENIED_FOLDERS + READ_ONLY_FOLDERS)


def _path_allowed(path: str, *, write: bool = False) -> bool:
    regexes = DENY_WRITE_REGEXES if write else DENY_READ_REGEXES
    return not any(regex.match(path) for regex in regexes)


def _abs(p: str, *, write: bool = False) -> Path:
    root = SANDBOX_ROOT.resolve()
    candidate = (root / p).resolve()
    if not candidate.is_relative_to(root):
        raise PermissionError(f"escape attempt blocked: {p}")
    if not _path_allowed(candidate.relative_to(root).as_posix(), write=write):
        raise PermissionError(f"access denied: {p}")
    return candidate

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
    p = _abs(path)
    if not p.is_dir():
        raise FileNotFoundError(str(p))
    root = SANDBOX_ROOT.resolve()
    return "\n".join(sorted(
        x.name for x in p.iterdir()
        if (x.resolve().is_relative_to(root)
            and _path_allowed(x.resolve().relative_to(root).as_posix()))))


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
    p = _abs(path, write=True)
    rel = p.relative_to(SANDBOX_ROOT).as_posix()
    denied_ancestors = [
        parent for parent in Path(rel).parents if str(parent) != "."
        and not _path_allowed(parent.as_posix(), write=True)]
    if not _path_allowed(rel, write=True) or denied_ancestors:
        raise ToolError(f"access denied: {path}")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return f"wrote {rel}"


@server.tool()
async def search_dir(pattern: str, path: str = ".") -> str:
    """Regex search under the project sandbox."""
    root = SANDBOX_ROOT.resolve()
    _abs(path)
    pat = re.compile(pattern)
    hits = []
    for f in root.joinpath(path).rglob("*"):
        if f.is_file():
            target = f.resolve()
            if not target.is_relative_to(root):
                continue
            rel = target.relative_to(root).as_posix()
            if not _path_allowed(rel):
                continue
            try:
                txt = f.read_text(errors="replace")
            except Exception:
                continue
            if pat.search(txt):
                hits.append(rel)
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
