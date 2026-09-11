SENSITIVE_FILES = [
    # environment / secrets
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "known_hosts",
    "*credentials*",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "*.tfvars",
    "terraform.tfstate*",
    "*.sqliterc",
    ".pgpass",
    ".my.cnf",
    ".docker/config.json",
    "*.kdbx",
]

DENIED_FOLDERS = [
    ".git",
    ".hg",
    ".svn",
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
]

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
DENY_ALL = DENY_READ + READ_ONLY_FOLDERS
