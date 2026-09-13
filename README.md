# rool-local-dev-mcp

A zero-trust filesystem bridge for AI agents: a sandboxed MCP server over
HTTP where the agent starts with **no access at all** and every capability
is an owner-provided allowance. OAuth 2.1 proves who is connected; consent
grants prove what they may touch; a deny-list draws lines no grant can
cross; and every mutation is proposed by the agent and applied only after
a human approves it.

## Security model

Access is layered, and each layer fails closed:

1. **Connection (OAuth 2.1)** — MCP clients authenticate via dynamic client
   registration and the device grant; the owner authenticates with GitHub.
   Authentication grants no filesystem access by itself.
2. **Folder consent** — the server starts knowing no folders. A client
   attempting a path gets `permission required`, which starts a consent
   flow; the owner grants specific folders, per-grantee, read-only or
   read-write, optionally with expiry. Grants are persisted and revocable;
   revocation instantly returns a folder to zero-privilege.
3. **Deny-list (always wins)** — a two-tier deny-list enforced at a single
   choke point (`_is_safe` in `mcp_fs_server.py`), independent of grants:
   even a fully granted folder cannot expose a denied file.

| Variable | Tier | Behavior |
| --- | --- | --- |
| `SENSITIVE_FILES` | `DENY_ALL` | Never readable or writable, anywhere |
| `DENIED_FOLDERS` | `DENY_ALL` | The folder and everything beneath it |
| `READ_ONLY_FOLDERS` | `DENY_WRITE` | Readable; writes always denied |

Env entries extend (not replace) the built-in defaults, parsed as CSV
(quote entries containing commas). Defaults cover credential stores
(`.ssh/`, `.aws/`, `.kube/`, `.gnupg/`, `.docker/`), key material
(`*.pem`, `*.key`, `id_rsa*`, …), VCS internals (`.git/`, `.hg/`,
`.svn/`), other package managers (`node_modules/`, `.pypirc`, `.npmrc`,
…), and infrastructure state (`terraform.tfstate*`, `*.tfvars`).

Deny-list semantics:

- Matching runs on the **resolved** path (symlinks resolved, `..`
  normalized), so indirection cannot reach a denied file.
- A pattern with no glob metacharacters is treated as a **folder** and
  denied along with everything beneath it; glob patterns match by name.
- **Deny always wins** — the deny-list is checked after path-grant
  resolution.
- Writes also check **ancestor directories**, so a denied folder cannot be
  created into via a nested `write_file`.

4. **Propose-then-approve** — the server never mutates on its own. Write
   tools land as proposals: the agent calls `propose_change`, which
   computes and stores a deterministic diff and returns a proposal id and
   an approval URL. A human approves or rejects — with commentary — on a
   loopback-only web UI (`127.0.0.1:8080`, never exposed through the
   tunnel); the held tool call resumes when the decision lands. A
   staleness guard hashes the target at propose time and blocks the apply
   if the file changed in between.

## Tools

| Tool | Gated by |
| --- | --- |
| `list_dir` | deny-list (read tier) |
| `read_file` | deny-list (read tier) |
| `search_dir` | deny-list (read tier) |
| `write_file` | deny-list (write tier) |
| `propose_change` / `wait_for_approval` | deny-list (write tier) + human approval |

## Quick start

```bash
pip install -r requirements.txt
cp .env.example .env   # then fill in the values
python ./launcher.py   # or ./start.sh
```

Expose it publicly with `ngrok http 8000` (or your own tunnel) and set
`BASE_URL` to the public URL. The approval UI binds `127.0.0.1:8080` and
is intentionally never proxied — only someone at the machine can approve.

## Auth flow

The server composes an OAuth 2.1 authorization server with the MCP
resource server. Owners authenticate with GitHub (a GitHub OAuth app is
the upstream identity provider); MCP clients authenticate with the server
itself via dynamic client registration and the OAuth device grant.

### Endpoints

| Path | Purpose |
| --- | --- |
| `/health` | Liveness probe |
| `/register` | Dynamic client registration (RFC 7591) |
| `/authorize` | OAuth authorization endpoint (consent-gated) |
| `/consent` | Owner consent page (GitHub-authenticated session) |
| `/device` | Device grant start (RFC 8628) |
| `/device/token` | Device token polling |
| `/token` | Authorization-code / refresh-token exchange |
| `/mcp` | MCP streamable-HTTP transport (Bearer-protected) |
| `/approve/<id>` | Proposal approval UI (loopback only) |

### Sequence

The flow below is the delegated-authorization path an MCP agent takes.
Steps 1-2 are done once per client; steps 3-9 repeat per session.

![Auth flow sequence diagram](docs/auth-flow.png)

(The diagram source lives at [`docs/auth-flow.mmd`](docs/auth-flow.mmd);
regenerate the image with [mermaid.ink](https://mermaid.ink) or any
mermaid renderer.)

### Notes

- **Registration requires `authorization_code` and `response_types:
  ["code"]`** even for device-only clients, because RFC 7591 metadata
  validation expects them. Headless clients should include both plus the
  device grant type.
- The device poll lives at `/device/token`, not `/token`.
- Access tokens are bearer tokens, stored hashed; refresh tokens rotate on
  use and can be revoked.
- The consent gate requires an owner session: only the GitHub account in
  `OWNER_GITHUB` can approve a client's device grant.
- The server enforces DNS-rebinding protection on the MCP transport
  (`allowed_hosts` / `allowed_origins` from `BASE_URL`).

## Why a deny-list in a grant world

Consent is about *what the agent asked for*; the deny-list is about *what
the owner never wants the agent to touch*, regardless of what it asks
for. An agent can be prompted (or hijacked) into requesting a folder that
happens to contain live secrets, SSH keys, or cloud credentials. The
deny-list draws those lines once, at the choke point, so no future grant
or sloppy path handling can cross them.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python ./launcher.py
```

`deny_list.py` holds the defaults and the tier model;
`mcp_fs_server.py` implements the MCP tools and the `_is_safe` gate;
`auth.py` composes the OAuth AS and consent flow; `db.py` is the store
for clients, tokens, grants, proposals, and audit records (SQLite, hashed
secrets, no plaintext tokens).
