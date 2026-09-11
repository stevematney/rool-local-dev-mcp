"""Default deny-lists for the filesystem sandbox.

SENSITIVE_FILES: glob patterns matched against sandbox-relative paths.
DENIED_FOLDERS: directory entries — the folder itself and everything
beneath it is denied. Override/extend via .env (comma-separated).

Kept deliberately conservative: these are universally agreed-to-be-
secret files across ecosystems. Project-specific additions belong in
.env, not here.
"""

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
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".ssh",
    ".aws",             # credentials/config
    ".gnupg",
    ".kube",            # cluster credentials
    ".docker",
]

DENY_LIST = SENSITIVE_FILES + DENIED_FOLDERS
