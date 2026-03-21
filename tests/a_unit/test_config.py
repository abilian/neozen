"""Tests for NeoZen configuration system."""

from __future__ import annotations

import tempfile
from datetime import timedelta
from pathlib import Path

import pytest

from neozen.config import (
    ConfigError,
    ConfigValidationError,
    DatabaseConfig,
    NeoZenConfig,
    NeoZenFactory,
    OAuthConfig,
    OAuthProviderConfig,
    PasswordConfig,
    SecurityConfig,
    SessionConfig,
    TOTPConfig,
    WebAuthnConfig,
    load_config,
    validate_config,
)
from neozen.config.loader import (
    expand_env_vars,
    expand_env_vars_recursive,
    find_config_file,
    parse_duration,
)


class TestParseDuration:
    """Tests for duration parsing."""

    def test_seconds(self) -> None:
        assert parse_duration("30s") == timedelta(seconds=30)
        assert parse_duration("60S") == timedelta(seconds=60)

    def test_minutes(self) -> None:
        assert parse_duration("5m") == timedelta(minutes=5)
        assert parse_duration("10M") == timedelta(minutes=10)

    def test_hours(self) -> None:
        assert parse_duration("1h") == timedelta(hours=1)
        assert parse_duration("24H") == timedelta(hours=24)

    def test_days(self) -> None:
        assert parse_duration("7d") == timedelta(days=7)
        assert parse_duration("30D") == timedelta(days=30)

    def test_weeks(self) -> None:
        assert parse_duration("2w") == timedelta(weeks=2)
        assert parse_duration("1W") == timedelta(weeks=1)

    def test_integer_seconds(self) -> None:
        assert parse_duration(3600) == timedelta(seconds=3600)
        assert parse_duration(86400) == timedelta(seconds=86400)

    def test_none(self) -> None:
        assert parse_duration(None) is None

    def test_invalid_format(self) -> None:
        with pytest.raises(ConfigError, match="Invalid duration format"):
            parse_duration("invalid")

    def test_invalid_unit(self) -> None:
        with pytest.raises(ConfigError, match="Invalid duration format"):
            parse_duration("10x")


class TestExpandEnvVars:
    """Tests for environment variable expansion."""

    def test_simple_expansion(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_VAR", "hello")
        assert expand_env_vars("${TEST_VAR}") == "hello"

    def test_with_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NONEXISTENT_VAR", raising=False)
        assert expand_env_vars("${NONEXISTENT_VAR:default_value}") == "default_value"

    def test_with_null_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NONEXISTENT_VAR", raising=False)
        assert expand_env_vars("${NONEXISTENT_VAR:null}") == ""

    def test_env_var_overrides_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_VAR", "actual")
        assert expand_env_vars("${TEST_VAR:default}") == "actual"

    def test_required_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("REQUIRED_VAR", raising=False)
        with pytest.raises(ConfigError, match="Required environment variable"):
            expand_env_vars("${REQUIRED_VAR}")

    def test_file_reference(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("secret-from-file\n")
            f.flush()
            try:
                monkeypatch.setenv("SECRET_FILE", f.name)
                assert expand_env_vars("${SECRET_FILE:file}") == "secret-from-file"
            finally:
                Path(f.name).unlink()

    def test_file_reference_missing_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MISSING_FILE", raising=False)
        with pytest.raises(ConfigError, match="file reference"):
            expand_env_vars("${MISSING_FILE:file}")

    def test_multiple_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VAR1", "hello")
        monkeypatch.setenv("VAR2", "world")
        assert expand_env_vars("${VAR1} ${VAR2}") == "hello world"

    def test_no_vars(self) -> None:
        assert expand_env_vars("plain text") == "plain text"


class TestExpandEnvVarsRecursive:
    """Tests for recursive environment variable expansion."""

    def test_dict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DB_URL", "postgres://localhost/db")
        data = {"database": {"url": "${DB_URL}"}}
        result = expand_env_vars_recursive(data)
        assert result["database"]["url"] == "postgres://localhost/db"

    def test_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SCOPE1", "read")
        monkeypatch.setenv("SCOPE2", "write")
        data = ["${SCOPE1}", "${SCOPE2}"]
        result = expand_env_vars_recursive(data)
        assert result == ["read", "write"]

    def test_nested(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECRET", "mysecret")
        data = {"level1": {"level2": {"secret": "${SECRET}"}}}
        result = expand_env_vars_recursive(data)
        assert result["level1"]["level2"]["secret"] == "mysecret"

    def test_non_string_values(self) -> None:
        data = {"count": 10, "enabled": True, "rate": 0.5}
        result = expand_env_vars_recursive(data)
        assert result == data


class TestLoadConfig:
    """Tests for configuration loading."""

    def test_default_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NEOZEN_CONFIG", raising=False)
        monkeypatch.chdir(tempfile.gettempdir())
        config = load_config()
        assert isinstance(config, NeoZenConfig)
        assert config.database.url == "sqlite+aiosqlite:///data/neozen.db"

    def test_load_from_file(self) -> None:
        toml_content = """
[database]
url = "sqlite:///test.db"
echo = true

[session]
lifetime = "24h"
cookie_name = "test_session"
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".toml") as f:
            f.write(toml_content)
            f.flush()
            try:
                config = load_config(f.name)
                assert config.database.url == "sqlite:///test.db"
                assert config.database.echo is True
                assert config.session.lifetime == timedelta(hours=24)
                assert config.session.cookie_name == "test_session"
            finally:
                Path(f.name).unlink()

    def test_file_not_found(self) -> None:
        with pytest.raises(ConfigError, match="Config file not found"):
            load_config("/nonexistent/path/config.toml")

    def test_invalid_toml(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".toml") as f:
            f.write("invalid toml [[[")
            f.flush()
            try:
                with pytest.raises(ConfigError, match="Invalid TOML"):
                    load_config(f.name)
            finally:
                Path(f.name).unlink()

    def test_env_var_expansion_in_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_DB_URL", "postgres://localhost/testdb")
        toml_content = """
[database]
url = "${TEST_DB_URL}"
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".toml") as f:
            f.write(toml_content)
            f.flush()
            try:
                config = load_config(f.name)
                assert config.database.url == "postgres://localhost/testdb"
            finally:
                Path(f.name).unlink()

    def test_oauth_providers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GOOGLE_ID", "google-client-id")
        monkeypatch.setenv("GOOGLE_SECRET", "google-secret")
        toml_content = """
[oauth.providers.google]
enabled = true
client_id = "${GOOGLE_ID}"
client_secret = "${GOOGLE_SECRET}"
scopes = ["openid", "email"]
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".toml") as f:
            f.write(toml_content)
            f.flush()
            try:
                config = load_config(f.name)
                assert "google" in config.oauth.providers
                google = config.oauth.providers["google"]
                assert google.enabled is True
                assert google.client_id == "google-client-id"
                assert google.client_secret == "google-secret"
                assert google.scopes == ("openid", "email")
            finally:
                Path(f.name).unlink()


class TestFindConfigFile:
    """Tests for configuration file discovery."""

    def test_env_var_priority(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".toml") as f:
            f.write("[database]\n")
            f.flush()
            try:
                monkeypatch.setenv("NEOZEN_CONFIG", f.name)
                found = find_config_file()
                assert found == Path(f.name)
            finally:
                Path(f.name).unlink()

    def test_env_var_file_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEOZEN_CONFIG", "/nonexistent/config.toml")
        with pytest.raises(ConfigError, match="Config file not found"):
            find_config_file()

    def test_no_config_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NEOZEN_CONFIG", raising=False)
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.chdir(tmpdir)
            found = find_config_file()
            assert found is None


class TestValidateConfig:
    """Tests for configuration validation."""

    def test_valid_config(self) -> None:
        config = NeoZenConfig(
            security=SecurityConfig(secret_key="a" * 32),
        )
        validate_config(config)

    def test_missing_secret_key(self) -> None:
        config = NeoZenConfig()
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_config(config)
        assert "security.secret_key is required" in str(exc_info.value)

    def test_short_secret_key(self) -> None:
        config = NeoZenConfig(
            security=SecurityConfig(secret_key="tooshort"),
        )
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_config(config)
        assert "at least 32 characters" in str(exc_info.value)

    def test_skip_secret_key_validation(self) -> None:
        config = NeoZenConfig()
        validate_config(config, require_secret_key=False)

    def test_invalid_password_lengths(self) -> None:
        config = NeoZenConfig(
            security=SecurityConfig(secret_key="a" * 32),
            password=PasswordConfig(min_length=20, max_length=10),
        )
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_config(config)
        assert "max_length must be >= min_length" in str(exc_info.value)

    def test_invalid_totp_digits(self) -> None:
        config = NeoZenConfig(
            security=SecurityConfig(secret_key="a" * 32),
            totp=TOTPConfig(digits=10),
        )
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_config(config)
        assert "totp.digits must be 6 or 8" in str(exc_info.value)

    def test_invalid_webauthn_origin(self) -> None:
        config = NeoZenConfig(
            security=SecurityConfig(secret_key="a" * 32),
            webauthn=WebAuthnConfig(origin="invalid-origin"),
        )
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_config(config)
        assert "origin must start with http://" in str(exc_info.value)

    def test_oauth_provider_missing_credentials(self) -> None:
        config = NeoZenConfig(
            security=SecurityConfig(secret_key="a" * 32),
            oauth=OAuthConfig(
                providers={
                    "google": OAuthProviderConfig(enabled=True),
                }
            ),
        )
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_config(config)
        errors = str(exc_info.value)
        assert "oauth.providers.google.client_id is required" in errors
        assert "oauth.providers.google.client_secret is required" in errors

    def test_multiple_errors(self) -> None:
        config = NeoZenConfig(
            password=PasswordConfig(min_length=0, max_length=-1),
        )
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_config(config, require_secret_key=False)
        errors = exc_info.value.errors
        assert len(errors) >= 2


class TestNeoZenFactory:
    """Tests for service factory."""

    def test_create_password_policy(self) -> None:
        config = NeoZenConfig(
            password=PasswordConfig(
                min_length=12,
                require_special=True,
                history_count=5,
            ),
        )
        factory = NeoZenFactory(config)
        policy = factory.create_password_policy()

        assert policy.min_length == 12
        assert policy.require_special is True
        assert policy.password_history_count == 5

    def test_create_totp_config(self) -> None:
        config = NeoZenConfig(
            totp=TOTPConfig(
                issuer="TestApp",
                digits=8,
                interval=60,
            ),
        )
        factory = NeoZenFactory(config)
        totp_config = factory.create_totp_config()

        assert totp_config.issuer == "TestApp"
        assert totp_config.digits == 8
        assert totp_config.interval == 60

    def test_create_webauthn_config(self) -> None:
        config = NeoZenConfig(
            webauthn=WebAuthnConfig(
                rp_id="example.com",
                rp_name="Example",
                origin="https://example.com",
                challenge_timeout=timedelta(minutes=10),
            ),
        )
        factory = NeoZenFactory(config)
        webauthn_config = factory.create_webauthn_config()

        assert webauthn_config.rp_id == "example.com"
        assert webauthn_config.rp_name == "Example"
        assert webauthn_config.origin == "https://example.com"
        assert webauthn_config.challenge_timeout_seconds == 600

    def test_get_session_lifetime_seconds(self) -> None:
        config = NeoZenConfig(
            session=SessionConfig(lifetime=timedelta(days=7)),
        )
        factory = NeoZenFactory(config)
        assert factory.get_session_lifetime_seconds() == 604800

    def test_get_sliding_window_seconds(self) -> None:
        config = NeoZenConfig(
            session=SessionConfig(sliding_window=timedelta(hours=2)),
        )
        factory = NeoZenFactory(config)
        assert factory.get_sliding_window_seconds() == 7200

    def test_get_sliding_window_none(self) -> None:
        config = NeoZenConfig(
            session=SessionConfig(sliding_window=None),
        )
        factory = NeoZenFactory(config)
        assert factory.get_sliding_window_seconds() is None

    def test_get_enabled_oauth_providers(self) -> None:
        config = NeoZenConfig(
            oauth=OAuthConfig(
                providers={
                    "google": OAuthProviderConfig(
                        enabled=True, client_id="g", client_secret="s"
                    ),
                    "github": OAuthProviderConfig(enabled=False),
                    "microsoft": OAuthProviderConfig(
                        enabled=True, client_id="m", client_secret="s"
                    ),
                }
            ),
        )
        factory = NeoZenFactory(config)
        enabled = factory.get_enabled_oauth_providers()
        assert set(enabled) == {"google", "microsoft"}

    def test_get_oauth_provider_config(self) -> None:
        config = NeoZenConfig(
            oauth=OAuthConfig(
                providers={
                    "google": OAuthProviderConfig(
                        enabled=True,
                        client_id="google-id",
                        client_secret="google-secret",
                        scopes=("openid", "email"),
                        extra={"hd": "example.com"},
                    ),
                }
            ),
        )
        factory = NeoZenFactory(config)
        provider_config = factory.get_oauth_provider_config("google")

        assert provider_config["client_id"] == "google-id"
        assert provider_config["client_secret"] == "google-secret"
        assert provider_config["scopes"] == "openid,email"
        assert provider_config["hd"] == "example.com"

    def test_get_oauth_provider_config_not_found(self) -> None:
        config = NeoZenConfig()
        factory = NeoZenFactory(config)
        with pytest.raises(KeyError):
            factory.get_oauth_provider_config("nonexistent")


class TestConfigTypes:
    """Tests for configuration type defaults."""

    def test_database_defaults(self) -> None:
        config = DatabaseConfig()
        assert "sqlite" in config.url
        assert config.pool_size == 5
        assert config.echo is False

    def test_session_defaults(self) -> None:
        config = SessionConfig()
        assert config.lifetime == timedelta(days=7)
        assert config.cookie_secure is True
        assert config.cookie_samesite == "lax"

    def test_password_defaults(self) -> None:
        config = PasswordConfig()
        assert config.min_length == 8
        assert config.require_uppercase is True
        assert config.check_hibp is False

    def test_totp_defaults(self) -> None:
        config = TOTPConfig()
        assert config.digits == 6
        assert config.interval == 30
        assert config.algorithm == "SHA1"

    def test_webauthn_defaults(self) -> None:
        config = WebAuthnConfig()
        assert config.rp_id == "localhost"
        assert config.user_verification == "preferred"

    def test_frozen_config(self) -> None:
        config = DatabaseConfig()
        with pytest.raises(AttributeError):
            config.url = "new-url"  # type: ignore[misc]
