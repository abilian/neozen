"""Configuration management CLI commands."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from typing import Any

from neozen.config import (
    ConfigError,
    ConfigValidationError,
    find_config_file,
    load_config,
    validate_config,
)


def _json_serializer(obj: Any) -> Any:
    """Custom JSON serializer for config objects."""
    if isinstance(obj, timedelta):
        total_seconds = int(obj.total_seconds())
        if total_seconds % 86400 == 0:
            return f"{total_seconds // 86400}d"
        if total_seconds % 3600 == 0:
            return f"{total_seconds // 3600}h"
        if total_seconds % 60 == 0:
            return f"{total_seconds // 60}m"
        return f"{total_seconds}s"
    msg = f"Object of type {type(obj)} is not JSON serializable"
    raise TypeError(msg)


def _mask_secrets(data: dict[str, Any]) -> dict[str, Any]:
    """Mask sensitive values in config data."""
    result: dict[str, Any] = {}
    secret_keys = {"secret_key", "password", "client_secret", "api_key"}

    for key, value in data.items():
        if isinstance(value, dict):
            result[key] = _mask_secrets(value)
        elif key in secret_keys and value:
            result[key] = "***MASKED***"
        else:
            result[key] = value

    return result


def validate_command(args: argparse.Namespace) -> int:
    """Validate configuration file."""
    try:
        config_path = getattr(args, "config_file", None)
        config = load_config(config_path)
        validate_config(config, require_secret_key=not args.skip_secret)
        print("Configuration is valid!")
        return 0
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ConfigValidationError as e:
        print(str(e), file=sys.stderr)
        return 1


def show_command(args: argparse.Namespace) -> int:
    """Show effective configuration."""
    try:
        config_path = getattr(args, "config_file", None)
        config = load_config(config_path)
        data = asdict(config)

        # Filter to specific section if requested
        section = getattr(args, "section", None)
        if section:
            if section not in data:
                print(f"Unknown section: {section}", file=sys.stderr)
                print(f"Available sections: {', '.join(data.keys())}", file=sys.stderr)
                return 1
            data = {section: data[section]}

        # Mask secrets unless --show-secrets is passed
        if not getattr(args, "show_secrets", False):
            data = _mask_secrets(data)

        print(json.dumps(data, indent=2, default=_json_serializer))
        return 0
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def path_command(args: argparse.Namespace) -> int:
    """Show configuration file path."""
    try:
        config_path = find_config_file()
        if config_path:
            print(config_path)
        else:
            print("No configuration file found (using defaults)")
        return 0
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def init_command(args: argparse.Namespace) -> int:
    """Generate template configuration file."""
    output_path = Path(args.output)

    if output_path.exists() and not args.force:
        print(f"File already exists: {output_path}", file=sys.stderr)
        print("Use --force to overwrite", file=sys.stderr)
        return 1

    template = _get_template(minimal=args.minimal)
    output_path.write_text(template, encoding="utf-8")
    print(f"Created {output_path}")
    return 0


def _get_template(*, minimal: bool = False) -> str:
    """Get configuration template content."""
    if minimal:
        return """\
# NeoZen Configuration (minimal)
# See: neozen config init --output neozen.toml (for full template)

[security]
# REQUIRED: Generate with: python -c "import secrets; print(secrets.token_hex(32))"
secret_key = "${NEOZEN_SECRET_KEY}"

[database]
url = "sqlite+aiosqlite:///data/neozen.db"
"""

    return """\
# NeoZen Configuration
# Environment variables: ${VAR}, ${VAR:default}, ${VAR_FILE:file}
# Durations: "7d", "24h", "30m", "60s"

# =============================================================================
# Database Configuration
# =============================================================================

[database]
url = "sqlite+aiosqlite:///data/neozen.db"
pool_size = 5
pool_recycle = 3600
echo = false

# =============================================================================
# Session Management
# =============================================================================

[session]
lifetime = "7d"
sliding_window = "1h"
cookie_name = "neozen_session"
cookie_secure = true
cookie_httponly = true
cookie_samesite = "lax"

# =============================================================================
# Password Policy
# =============================================================================

[password]
min_length = 8
max_length = 128
require_uppercase = true
require_lowercase = true
require_digit = true
require_special = false
check_hibp = false
history_count = 0

# =============================================================================
# TOTP (Two-Factor Authentication)
# =============================================================================

[totp]
issuer = "NeoZen"
digits = 6
interval = 30
algorithm = "SHA1"
backup_code_count = 10
backup_code_length = 8

# =============================================================================
# WebAuthn / Passkeys
# =============================================================================

[webauthn]
rp_id = "localhost"
rp_name = "My Application"
origin = "http://localhost:8000"
challenge_timeout = "5m"
user_verification = "preferred"

# =============================================================================
# OAuth Client (Social Login)
# =============================================================================

[oauth]
state_lifetime = "10m"
default_scopes = ["openid", "email", "profile"]

[oauth.providers.google]
enabled = false
client_id = "${GOOGLE_CLIENT_ID:}"
client_secret = "${GOOGLE_CLIENT_SECRET:}"
scopes = ["openid", "email", "profile"]

[oauth.providers.github]
enabled = false
client_id = "${GITHUB_CLIENT_ID:}"
client_secret = "${GITHUB_CLIENT_SECRET:}"
scopes = ["user:email", "read:user"]

# =============================================================================
# Security
# =============================================================================

[security]
# REQUIRED: Generate with: python -c "import secrets; print(secrets.token_hex(32))"
secret_key = "${NEOZEN_SECRET_KEY}"

[security.rate_limit]
enabled = false
login_attempts = 5
login_window = "15m"
registration_attempts = 3
registration_window = "1h"

[security.lockout]
enabled = false
threshold = 5
duration = "30m"
reset_on_success = true

# =============================================================================
# Email
# =============================================================================

[email]
provider = "console"
from_address = "noreply@example.com"
from_name = "NeoZen"

[email.smtp]
host = "localhost"
port = 587
use_tls = true

# =============================================================================
# Authorization
# =============================================================================

[authorization]
builtin_roles = ["admin", "user"]
first_user_roles = ["admin", "user"]

# =============================================================================
# Admin UI
# =============================================================================

[admin]
enabled = true
path_prefix = "/admin"
require_role = "admin"

# =============================================================================
# Logging
# =============================================================================

[logging]
level = "INFO"
audit_enabled = false
"""


__all__ = ["init_command", "path_command", "show_command", "validate_command"]
