"""Tests for PKCE (Proof Key for Code Exchange) module."""

from __future__ import annotations

import pytest

from neozen.core.oauth import (
    PKCEVerificationFailedError,
    compute_s256_challenge,
    verify_pkce,
)


class TestComputeS256Challenge:
    """Tests for compute_s256_challenge function."""

    def test_known_value(self) -> None:
        # RFC 7636 Appendix B test vector
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        assert compute_s256_challenge(verifier) == expected

    def test_produces_base64url_without_padding(self) -> None:
        # The output should be base64url encoded without = padding
        result = compute_s256_challenge("test_verifier_43_chars_long_xxxxxxxxxxxx")
        assert "=" not in result
        assert "+" not in result
        assert "/" not in result

    def test_deterministic(self) -> None:
        verifier = "test_verifier_value"
        result1 = compute_s256_challenge(verifier)
        result2 = compute_s256_challenge(verifier)
        assert result1 == result2

    def test_different_verifiers_produce_different_challenges(self) -> None:
        result1 = compute_s256_challenge("verifier_one")
        result2 = compute_s256_challenge("verifier_two")
        assert result1 != result2


class TestVerifyPkce:
    """Tests for verify_pkce function."""

    def test_plain_method_success(self) -> None:
        verifier = "test_verifier_43_chars_long_xxxxxxxxxxxx"
        # No exception raised means success
        verify_pkce(verifier, verifier, "plain")

    def test_plain_method_failure(self) -> None:
        with pytest.raises(PKCEVerificationFailedError):
            verify_pkce("verifier", "different_challenge", "plain")

    def test_s256_method_success(self) -> None:
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        # No exception raised means success
        verify_pkce(verifier, challenge, "S256")

    def test_s256_method_failure_wrong_verifier(self) -> None:
        challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        with pytest.raises(PKCEVerificationFailedError):
            verify_pkce("wrong_verifier", challenge, "S256")

    def test_s256_method_failure_wrong_challenge(self) -> None:
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        with pytest.raises(PKCEVerificationFailedError):
            verify_pkce(verifier, "wrong_challenge", "S256")

    def test_unsupported_method_raises_error(self) -> None:
        with pytest.raises(PKCEVerificationFailedError):
            verify_pkce("verifier", "challenge", "unsupported")  # type: ignore[arg-type]
