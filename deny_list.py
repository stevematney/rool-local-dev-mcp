"""Default deny-lists for the filesystem sandbox.

Two tiers:
- DENY_READ: never readable, never writable. Secrets, key material,
  credential stores, VCS internals.
- DENY_WRITE: readable, never writable. Generated/ephemeral content
  (dependency trees, caches) where read access helps the agent but a
  write would be corrupting.

Glob patterns matched against sandbox-relative paths. Folder entries
deny the folder itself and everything beneath it. Override/extend via
.env (comma-separated SENSITIVE_FILES / DENIED_FOLDERS / READ_ONLY_FOLDERS).

Kept deliberately conservative: universally agreed-to-be-secret (or
universally generated) entries only. Project-specific additions belong
in .env, not here.
"""

# never read, never write
SENSITIVE_FILES = [
    # environment / secrets
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",            # java keystores
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "known_hosts",
    "*credentials*",
    ".npmrc",           # can hold auth tokens
    ".pypirc",          # PyPI tokens
    ".netrc",
    "*.tfvars",         # terraform variable files (often secrets)
    "terraform.tfstate*",  # state can contain secrets
    "*.sqliterc",
    ".pgpass",
    ".my.cnf",
    ".docker/config.json",  # registry credentials
    "*.kdbx",           # keepass databases
]

DENIED_FOLDERS = [
    ".git",
    ".hg",
    ".svn",
    ".ssh",
    ".aws",             # credentials/config
    ".gnupg",
    ".kube",            # cluster credentials
    ".docker",
]

# readable, never writable (generated/ephemeral content)
READ_ONLY_FOLDERS = [
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
]

DENY_READ = SENSITIVE_FILES + DENIED_FOLDERS
DENY_ALL = DENY_READ + READ_ONLY_FOLDERS   # never write
