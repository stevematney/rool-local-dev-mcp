# rool-fs MCP — Feature list

A personal, least-privilege MCP server that exposes allow-listed folders on
a local machine to remote MCP clients over a durable
tunnel, with OAuth 2.1 connection auth and propose-then-approve
change control.

Status legend: `proposed` → `design` → `committed` → `built` → `done` | `deferred` | `rejected`

---

## Build order (necessity-first)

Nothing downstream works until the transport is real, so networking and a
repeatable boot come first. Each phase is independently testable end-to-end.
`[x]` = shipped/verified · `[ ]` = not yet.

- [x] **P1 — Durable endpoint** — stable ngrok URL; stable ngrok domain held outside the repo — `.env` only. · Ref F
- [x] **P1 — Single-command startup** — `launcher.py` (process supervision) boots MCP server (:8000) + tunnel; Ctrl+C tears both down; prints ready after `/health` passes. *(Approval UI on :8080 lands in P4.)* · Ref F
- [x] **P1 — Minimal server boots** — streamable-HTTP MCP server on :8000 via `MCPServer.run_streamable_http_async`; `/health` answers `200 OK` through the tunnel. · Ref A
- [x] *Reachability smoke test from the development machine*: verified `HTTP 200 / OK mcp-fs p1` end to end. · Ref F
- [x] **P1.5 — Minimal sandboxed tools** — `list_dir`, `read_file`, `write_file`, `search_dir` with path gate; *`write_file` superseded by `propose_change` in P4*; verified over MCP client session (`INITIALIZED: rool-fs`, tools listed, `list_dir` round trip). · Ref F
- [x] **P2 — OAuth 2.1 connection auth** — provider + persistence + browser consent; includes dynamic client registration, device flow for headless clients, bearer auth enforced at the transport. Verified end-to-end over the tunnel (register → device code → owner consent → token → authenticated MCP call). Fork 2: loopback consent, API-only tunnel. · Ref A
- [x] **P2 — Refresh-token rotation + revocation** — single-use refresh tokens, rotated on exchange; access/refresh revocation persisted. · Ref A
- [x] **P2.5 — Sensitive-file blocklist** — deny-list (e.g. `.env`, secrets, keys) enforced on every tool op, independent of grants; even a granted folder cannot expose them. *(Shipped Sep 17, 2026: `app/deny_list.py` two-tier model (DENY_ALL / DENY_WRITE), env extension beyond built-in defaults, enforced at the `_is_safe` choke point; `rool_fs.db` added to defaults; write ancestor checks.)* · Ref B
- [ ] **P3 — Zero-privilege folder consent** — grants, per-folder scopes, revoke, enforcement, cwd implicit grant · Ref B
- [ ] **P3 — In-repo test suite** — port the unit tests an agent previously ran ad hoc (auth, deny-list, path enforcement) into the app itself so they ship with the repo and run on every change · Ref F
- [ ] **P4 — `propose_change` + `wait_for_approval`** — held request, durable sqlite state · Ref C
- [ ] **P4 — Web approve/deny UI** on `127.0.0.1:8080` — diff view, approve/reject with commentary · Ref D
- [ ] **P4 — Staleness guard** — hash at propose time, block apply if file changed · Ref C
- [ ] **P5 — Browser Notification API** (tab open) · Ref D
- [ ] **P5 — Service Worker + VAPID push** (tab closed) · Ref D
- [ ] **P5 — SSE auto-refresh** on the UI · Ref D
- [ ] **P6 — Audit log + replay** · Ref F
- [ ] **P6 — git integration** — diffs against `git diff`, `rool/` branch, commits on your signal · Ref F
- [ ] **P7 — Cross-device push** · Ref D

Build down, not across: **transport → identity → consent → approval → UX → polish.**
Each phase leaves the system in a working, testable state.

**Checked off P1 + P1.5** — verified end-to-end through the tunnel (Sep 7, 2026):
endpoint reachable, launcher supervises cleanly, server boots, tools respond.

---

## A. Connection auth (OAuth 2.1, MCP spec 2025-06-18)

| Feature | Status | Notes |
|---|---|---|
| OAuth 2.1 flow (PKCE, dynamic client registration, RFC 8707 resource indicators) | `committed` | Server ships with the auth machinery in the official MCP SDK; we implement a thin provider + persistence only. |
| Browser consent on first connect | `committed` | Owner approves in a browser; short-lived access token issued. |
| Automatic refresh-token rotation | `design` | Single-use refresh tokens, stored hashed, rotated on every exchange; no manual rotation. |
| Revocation (per client / per session) | `design` | Tiny CLI or server page; revoke the client, the session, or all sessions. |
| **OAuth ≠ permission** | `design` | OAuth proves *who* is connected. It grants **no** folder and **no** write. Permission layers below are strictly separate. |

## B. Zero-privilege folder consent

| Feature | Status | Notes |
|---|---|---|
| **Zero privilege by default** | `design` | Server starts knowing **no** folders. Client attempts a path → server answers `permission required` → consent flow starts. No `REPO_ROOT` constant. |
| Per-folder consent grant | `design` | "Permission required for `/Users/you/projects/app`". Grants persisted (sqlite), revocable; record: folder, grantee, scope (read-only vs read-write), granted-at, optional expiry. **A folder grant implicitly covers all its sub-folders** — grant the root, reach the whole tree. |
| Path enforcement at every op | `committed` | Resolve against the granted set; anything outside → `PermissionError` + audit entry. Path resolution + prefix check makes escapes structurally impossible. |
| Sensitive-file blocklist | `done` | Deny-list enforced at the tool layer, in addition to (not instead of) path grants. Defaults: `.env`, `.env.*`, `*.pem`, `*.key`, `.git/`, `rool_fs.db`; configurable. Deny wins over any grant — explicit or implicit (session-init); denied paths are globally blocked and even owner intent cannot override them in the normal flow. Reads, writes, and listings all excluded. Possible future escape hatch: one-time exclusions, requiring explicit per-approval consent each time — out of the normal process, deliberately loud. Not planned for initial build. |
| Held request until decision | `design` | Denied read op starts the consent flow; the tool call HOLDS (same mechanism as proposal approval — long-poll sqlite, not client polling) until you approve/deny in the browser. Approval persists the grant to sqlite automatically; denial returns the refusal. No re-polling either path. |
| Implicit grant at session init | `design` | The initialization flag that defines the session root folder is an implicit grant: that folder enters the allow list automatically, with no request ceremony. Expected form: launching `start.sh` from a repo root grants cwd (resolve `$PWD` before the script's own `cd` to the repo dir, so the launch site — not the repo location — is what gets granted). An optional explicit path argument overrides cwd; refuse to start if cwd is `$HOME` or `/` (accidental broad grant). All other folders still earn consent on first denied access. Deny-list wins over implicit grants as over any grant. |
| Revoke folder grant | `design` | Revoked folder instantly returns to zero-privilege. |

Inversion of least-privilege: express **zero grants**, earn each folder exactly when
access is needed. The owner surfaces any `permission required` in chat and decides in the open.

## C. Forced approval mode

| Feature | Status | Notes |
|---|---|---|
| **Propose-then-apply as default** | `committed` | Server never mutates on its own. `propose_change` computes and stores a deterministic diff — lands nothing. |
| Human-only approval | `committed` | Write path requires human `approve`; no auto-apply, no soft-mode default. |
| Approval/commentary feeds back into the agent's next turn | `design` | "yes, but also x, y, z" or "no, do this instead" is stored with the decision and fed back to the agent as an instruction (recommend an instruction file / prompt is inspectable). |
| Reject path | `design` | Proposal voided, commentary fed back, nothing written. |
| Staleness guard | `design` | Server hashes target file at propose time; if file hash differs when decision lands → conflict, no apply. Never clobber concurrent edits. |

## D. Web approval UI

| Feature | Status | Notes |
|---|---|---|
| Server also serves the approve/deny web page | `committed` | Same server app hosts the UI; route like `/approve/<proposal_id>`. |
| **Loopback-only UI** | `design` | UI binds `127.0.0.1:8080`; the tunnel proxies only the MCP port `:8000`. Approval form is **never** exposed to the tunnel/public internet — only someone on the machine can approve. This is the security-critical design choice; keep it. |
| Diff rendered from stored proposal | `design` | Unified diff (create/edit/delete badge) computed at propose time, rendered with escaping. Replayable, auditable. |
| Approve with commentary | `design` | Textarea → stored with proposal → returned to held request → fed into next-turn instructions. |
| Reject with commentary | `design` | Same; proposal voided. |
| Held request until decision | `design` | `propose_change` returns proposal_id + URL immediately; `wait_for_approval` long-polls sqlite till decision. Durable state → resumable/retry-safe even if the agent's HTTP call times out and it re-polls. **Same held-call mechanism serves folder-consent grants (Ref B) — one implementation, both flows.** |
| SSE auto-refresh (light) | `deferred` | `EventSource` keeps an open tab live. Nice, cheap. |
| Browser Notification API (same-machine, tab open) | `design` | Baseline: `new Notification(...)` fires from the open tab, no push at all. One permission prompt; loopback is a secure context so it works on `127.0.0.1:8080`. Covers the "tab open but not focused" case. |
| **Service Worker + Web Push (same-machine, tab CLOSED)** | `design` | The good one (owner steering). SW alone can't wake a closed tab — push delivery does. Implementation is cheap: VAPID keypair generated locally (no signup, no FCM account — the browser's built-in push endpoint is used); server stores the subscription on first visit; each new proposal then triggers a signed push POST → browser wakes the SW → `showNotification()` → user clicks → approve page opens. Works on loopback (secure context). ~25 lines of SW/subscription JS + a few server lines. |
| Cross-device Web Push (different machine) | `deferred` | Out of scope (owner decision). Same SW/push machinery could later notify other devices, but worth it only if the user wants to receive approvals away from the machine. |
| SSE from the server→SW (rejected) | `rejected` | Why not: an SW is killed when the last tab for its scope closes (idle termination, ~tens of seconds). No page → no clients → no liveness; an SSE/EventSource the SW left open dies with it. So SSE can only cover the tab-open case — exactly what the Notification API already does. The only dependable wake of a dead SW is push (or permission-gated periodic background sync at service cadence). |
| Engineering note — "third party" | `design` | The push delivery isn't a vendor we run: we generate a VAPID keypair locally, the server POSTs to the browser-supplied subscription URL (the browser gave us that URI itself). That's the browser/OS built-in delivery plumbing, not a SaaS we control or sign up for. No FCM account. |
| CSRF / one-time page token | `design` | Loopback lowers risk but token the page anyway. |

Sequence: **Connect → consent folder → propose (returns URL, holds) → you approve/reject w/ commentary → held call returns decision → apply (only if approved & fresh)**.

## F. Server / tools / transport

| Aspect | Status | Notes |
|---|---|---|
| Sandboxed fs tools (list/read/write/search) | `built` | `list_dir`, `read_file`, `write_file`, `search_dir`; every path validated; read tools verified over the tunnel |
| Session-aware tooling | `design` | A tool (e.g. `list_grants`/`session_info`) for the agent to see its granted folders — critically distinguishing the **current session root** (cwd granted at startup) from other grants, since absolute-path listings are otherwise indistinguishable. |
| Local persistence | `committed` | sqlite: clients, tokens, grants, proposals, audit; hashed secrets, no plaintext tokens |
| Audit log | `design` | grants, proposals, approvals, denials, token rolls timestamped, replayable |
| git integration | `design` | propose diffs against `git diff`; approval targets a `rool/` branch; commits only with your signal |
| Durable endpoint | `done` | Stable ngrok domain; never committed to the repo — `.env` only |
| Single-command startup | `built` | `launcher.py` boots MCP server (:8000) + tunnel; prints ready after `/health`; approve UI (:8080) arrives with P4 |
| Chat as control plane | `committed` | I hand you the approve URL; diffs/summaries/decisions round-trip through chat |

## Sequenced

Connect (OAuth) → Consent folder (grant) → Propose (diff, held) → Approve/reject (web, w/ commentary) → Apply (only if approved) → Audit trail throughout.

## Open questions / next to solve

- Consent UX: web page (loopback) or chat? Likely web page for both folder-consent and change-approval, chat hand-off of URLs.
- Held-call timeout for consent and proposals: return "still pending + URL" after N seconds rather than hanging the agent session; retryable. (Recommend the same value for both flows.)
- Grant scope defaults: read-only default, writes still require approval? Recommend: writeable generally, approval is the gate; read-only grants optional.
- Approval/commentary transport: instruction file read next turn (inspectable) vs injected directly. (Recommend: instruction file.)
- Staleness conflict: auto-apply after approve + hash mismatch → block + re-propose. (Recommend: block + re-propose.)
- Naming: `rool-fs` provisional.
