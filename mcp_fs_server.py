#!/usr/bin/env python3
"""
mcp_fs_server.py — P1 minimal MCP server skeleton (rool-fs).

Phase target: prove the tunnel loop. Serves a streamable-HTTP MCP server on
:8000 at /mcp, plus a /health endpoint, plus sandboxed fs tools behind a
path gate. Auth = NONE YET (P2). Approval = NONE YET (P4).

Run:  python3 mcp_fs_server.py            (from this directory)
"""
from __future__ import annotations

import re
from pathlib import Path

from mcp.server import MCPServer
from starlette.requests import Request
from starlette.responses import Response

PORT = 8000
BIND_HOST = "::"          # both stacks; ngrok probes IPv6 loopback first
# project folder = sandbox for P1
SANDBOX_ROOT = Path(__file__).resolve().parent

server = MCPServer(
    name="rool-fs",
    title="rool-fs project filesystem",
    instructions="Sandboxed read/write tools scoped to the project folder.",
)


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
            try:
                txt = f.read_text(errors="replace")
            except Exception:
                continue
            if pat.search(txt):
                hits.append(f.relative_to(root).as_posix())
    if not hits:
        return "(no matches)"
    return "\n".join(sorted(hits))


@server.custom_route("/health", methods=["GET"])
async def health(_: Request) -> Response:
    return Response(content="OK mcp-fs p1\n", media_type="text/plain")


async def main() -> None:
    print(f"MCP fs server (P1) on {BIND_HOST}:{PORT}  sandbox={SANDBOX_ROOT}")
    await server.run_streamable_http_async(
        host=BIND_HOST,
        port=PORT,
        streamable_http_path="/mcp",
    )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
