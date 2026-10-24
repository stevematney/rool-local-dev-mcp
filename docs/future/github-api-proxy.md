# Proposal: GitHub API proxy through the MCP server

Status: proposed · Date: 2026-10-24

## Idea

Let an agent make GitHub API requests through this MCP server, using the
GitHub OAuth token the server already holds for the authenticated owner —
rather than the agent holding its own PAT.

The server already does the hard part: device flow + PKCE, browser consent,
token persistence, single-use refresh rotation, bearer auth at the transport.
A GitHub OAuth app registered for this purpose plugs into the same machinery;
the agent never sees a credential at all.

## Why this beats a PAT

A PAT's only protection is its scope list. It is long-lived, cannot be
rotated per use, and cannot be revoked without invalidating everything. A
proxied OAuth token gets rotation, immediate per-session revocation, and —
the important part — a choke point that sees *intent*, not just credentials:

- **Reads** (search, read issues/PRs/files): pass through under the blanket
  consent given at connect time.
- **Writes** (open/merge PR, push, create/delete branch): do not execute.
  Each call becomes a proposal, surfaced at the consent gate, executed only
  on human approval — the same shape as the planned P4 approval flow.
- **Diff review for git writes**: an agent asking to change code proposes the
  patch; the approval UI renders it. Much stronger than approving an opaque
  API call after the fact.

## Design constraints / risks

- **Two credential classes.** Existing tokens are audience-scoped (RFC 8707)
  to this MCP resource. GitHub tokens are a separate audience with separate
  lifetime. Model them explicitly; don't let the tool layer treat "has a
  token" as uniform.
- **Confused deputy on approvals.** The proposal shown to the human must be
  the literal request body the tool will send, and the server must execute
  exactly what was approved — not a re-derivation of it. Otherwise the gate
  is decorative.
- **Blast radius.** Because every write is individually approved, requesting
  a broad scope (e.g. `repo`) is defensible: the token alone cannot act; the
  consent gate is the second factor. Same posture as "consent deny-always-
  wins", extended from filesystem paths to API verbs.
- **Rate limits / abuse shape.** Runaway loops burn the owner's per-token
  rate budget and can flag the account. Mitigations: per-session call budget;
  no write tool exposed without an active approved session.

## Summary

Coherent extension of the existing architecture: agent holds no credential,
human holds consent, server is the single choke point. Without the proposal
gate, the idea degrades to a PAT with extra steps and is not worth doing.
