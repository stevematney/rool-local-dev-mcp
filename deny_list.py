import csv
import os

sensitive_file_defaults = [
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.jks",
    "**/*.kdbx",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/id_ecdsa*",
    "**/known_hosts",
    "**/*credentials*",
    "**/.npmrc",
    "**/.pypirc",
    "**/.netrc",
    "**/.pgpass",
    "**/.my.cnf",
    "**/.docker/config.json",
    "**/*.sqliterc",
    "**/*.tfvars",
    "**/terraform.tfstate*",
]

denied_folder_defaults = [
    "**/.git", "**/.git/**",
    "**/.hg", "**/.hg/**",
    "**/.svn", "**/.svn/**",
    "**/.ssh", "**/.ssh/**",
    "**/.aws", "**/.aws/**",
    "**/.gnupg", "**/.gnupg/**",
    "**/.kube", "**/.kube/**",
    "**/.docker", "**/.docker/**",
]

read_only_folder_defaults = [
    "**/.venv", "**/.venv/**",
    "**/venv", "**/venv/**",
    "**/__pycache__", "**/__pycache__/**",
    "**/node_modules", "**/node_modules/**",
    "**/dist", "**/dist/**",
    "**/build", "**/build/**",
    "**/.pytest_cache", "**/.pytest_cache/**",
    "**/.mypy_cache", "**/.mypy_cache/**",
    "**/.ruff_cache", "**/.ruff_cache/**",
]


def _env_list(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return next(csv.reader([raw])) if raw.strip() else []


DENY_ALL = _env_list("SENSITIVE_FILES") + _env_list("DENIED_FOLDERS") + sensitive_file_defaults + denied_folder_defaults
DENY_WRITE = _env_list("READ_ONLY_FOLDERS") + read_only_folder_defaults
