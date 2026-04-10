"""Tests for i18n: catalogs, translator, locale negotiation."""

from __future__ import annotations

import pytest

from neozen.core.i18n import (
    Catalog,
    Translator,
    builtin_translator,
    negotiate_locale,
    parse_accept_language,
)

# =============================================================================
# Catalog
# =============================================================================


class TestCatalog:
    def test_get(self) -> None:
        c = Catalog({"hi": "Hello", "bye": "Goodbye"})
        assert c.get("hi") == "Hello"
        assert c.get("bye") == "Goodbye"
        assert c.get("missing") is None

    def test_contains(self) -> None:
        c = Catalog({"hi": "Hello"})
        assert "hi" in c
        assert "missing" not in c

    def test_empty_catalog(self) -> None:
        c = Catalog()
        assert c.get("anything") is None


# =============================================================================
# Translator
# =============================================================================


@pytest.fixture
def translator() -> Translator:
    t = Translator(default_locale="en")
    t.add_catalog(
        "en",
        Catalog({
            "hi": "Hello",
            "welcome": "Welcome, {name}!",
            "english_only": "Only in English",
        }),
    )
    t.add_catalog(
        "fr",
        Catalog({
            "hi": "Bonjour",
            "welcome": "Bienvenue, {name}!",
        }),
    )
    return t


class TestTranslator:
    def test_basic_translation(self, translator: Translator) -> None:
        assert translator.gettext("hi", locale="en") == "Hello"
        assert translator.gettext("hi", locale="fr") == "Bonjour"

    def test_default_locale(self, translator: Translator) -> None:
        assert translator.gettext("hi") == "Hello"

    def test_kwargs_substitution(self, translator: Translator) -> None:
        result = translator.gettext("welcome", locale="fr", name="Alice")
        assert result == "Bienvenue, Alice!"

    def test_fallback_to_default(self, translator: Translator) -> None:
        # "english_only" is not in fr catalog -- falls back to en
        result = translator.gettext("english_only", locale="fr")
        assert result == "Only in English"

    def test_missing_message_returns_id(self, translator: Translator) -> None:
        result = translator.gettext("nope", locale="fr")
        assert result == "nope"

    def test_missing_message_with_kwargs(self, translator: Translator) -> None:
        result = translator.gettext("Hello {name}", name="World")
        assert result == "Hello World"

    def test_regional_fallback(self) -> None:
        t = Translator(default_locale="en")
        t.add_catalog("en", Catalog({"hi": "Hello"}))
        t.add_catalog("fr", Catalog({"hi": "Bonjour"}))

        # fr-CA should fall back to fr
        assert t.gettext("hi", locale="fr-CA") == "Bonjour"

    def test_unknown_locale_uses_default(self) -> None:
        t = Translator(default_locale="en")
        t.add_catalog("en", Catalog({"hi": "Hello"}))

        assert t.gettext("hi", locale="de") == "Hello"

    def test_has_locale(self, translator: Translator) -> None:
        assert translator.has_locale("en")
        assert translator.has_locale("fr")
        assert not translator.has_locale("de")

    def test_available_locales(self, translator: Translator) -> None:
        locales = translator.available_locales()
        assert "en" in locales
        assert "fr" in locales

    def test_merge_catalog(self) -> None:
        t = Translator()
        t.add_catalog("en", Catalog({"hi": "Hi"}))
        t.merge_catalog("en", Catalog({"bye": "Bye"}))

        assert t.gettext("hi", locale="en") == "Hi"
        assert t.gettext("bye", locale="en") == "Bye"

    def test_merge_overwrites_existing(self) -> None:
        t = Translator()
        t.add_catalog("en", Catalog({"hi": "Hi"}))
        t.merge_catalog("en", Catalog({"hi": "Hello"}))

        assert t.gettext("hi", locale="en") == "Hello"

    def test_case_insensitive_locale(self, translator: Translator) -> None:
        assert translator.gettext("hi", locale="EN") == "Hello"
        assert translator.gettext("hi", locale="FR") == "Bonjour"
        assert translator.gettext("hi", locale="Fr-CA") == "Bonjour"


# =============================================================================
# Accept-Language parsing
# =============================================================================


class TestParseAcceptLanguage:
    def test_empty(self) -> None:
        assert parse_accept_language("") == []
        assert parse_accept_language(None) == []

    def test_single_locale(self) -> None:
        result = parse_accept_language("en-US")
        assert len(result) == 1
        assert result[0].tag == "en-us"
        assert result[0].quality == pytest.approx(1.0)

    def test_multiple_locales_with_quality(self) -> None:
        result = parse_accept_language("en-US,fr;q=0.9,de;q=0.8")
        assert len(result) == 3
        assert result[0].tag == "en-us"
        assert result[1].tag == "fr"
        assert result[1].quality == pytest.approx(0.9)
        assert result[2].tag == "de"

    def test_sorted_by_quality(self) -> None:
        # Lower quality first in input
        result = parse_accept_language("de;q=0.5,en;q=0.9")
        assert result[0].tag == "en"
        assert result[1].tag == "de"

    def test_invalid_quality_treated_as_1(self) -> None:
        result = parse_accept_language("en;q=invalid")
        assert result[0].quality == pytest.approx(1.0)


# =============================================================================
# Locale negotiation
# =============================================================================


class TestNegotiateLocale:
    def test_default_when_no_inputs(self) -> None:
        locale = negotiate_locale(
            available=["en", "fr"],
            default="en",
        )
        assert locale == "en"

    def test_ui_locales_priority(self) -> None:
        locale = negotiate_locale(
            ui_locales="fr",
            user_preference="de",
            accept_language="es",
            available=["en", "fr", "de", "es"],
            default="en",
        )
        assert locale == "fr"

    def test_ui_locales_as_list(self) -> None:
        locale = negotiate_locale(
            ui_locales=["zh", "fr"],  # zh not available, falls to fr
            available=["en", "fr"],
            default="en",
        )
        assert locale == "fr"

    def test_ui_locales_string_with_spaces(self) -> None:
        locale = negotiate_locale(
            ui_locales="zh fr de",
            available=["en", "fr"],
            default="en",
        )
        assert locale == "fr"

    def test_user_preference_when_no_ui_locales(self) -> None:
        locale = negotiate_locale(
            user_preference="fr",
            accept_language="de",
            available=["en", "fr", "de"],
            default="en",
        )
        assert locale == "fr"

    def test_accept_language_when_no_preference(self) -> None:
        locale = negotiate_locale(
            accept_language="fr;q=0.9,en;q=0.8",
            available=["en", "fr"],
            default="en",
        )
        assert locale == "fr"

    def test_regional_fallback_in_ui_locales(self) -> None:
        # fr-CA isn't available, but fr is
        locale = negotiate_locale(
            ui_locales="fr-CA",
            available=["en", "fr"],
            default="en",
        )
        assert locale == "fr"

    def test_no_match_returns_default(self) -> None:
        locale = negotiate_locale(
            ui_locales="zh",
            user_preference="ja",
            accept_language="ko",
            available=["en", "fr"],
            default="en",
        )
        assert locale == "en"

    def test_default_not_in_available(self) -> None:
        locale = negotiate_locale(
            available=["fr", "de"],
            default="en",
        )
        # Default not available, should return first available
        assert locale == "fr"


# =============================================================================
# Built-in translator
# =============================================================================


class TestBuiltinTranslator:
    def test_english_password_reset(self) -> None:
        msg = builtin_translator.gettext(
            "email.password_reset.subject",
            locale="en",
            app_name="My App",
        )
        assert msg == "Reset your My App password"

    def test_french_password_reset(self) -> None:
        msg = builtin_translator.gettext(
            "email.password_reset.subject",
            locale="fr",
            app_name="My App",
        )
        assert "My App" in msg
        assert "mot de passe" in msg.lower() or "passe" in msg.lower()

    def test_french_otp(self) -> None:
        msg = builtin_translator.gettext(
            "email.otp.subject",
            locale="fr",
            app_name="App",
            code="123456",
        )
        assert "123456" in msg
        assert "App" in msg

    def test_fallback_for_unknown_locale(self) -> None:
        # Spanish not in built-in -- should fall back to English
        msg = builtin_translator.gettext(
            "email.password_reset.subject",
            locale="es",
            app_name="My App",
        )
        assert msg == "Reset your My App password"

    def test_error_messages_translated(self) -> None:
        en = builtin_translator.gettext("error.invalid_credentials", locale="en")
        fr = builtin_translator.gettext("error.invalid_credentials", locale="fr")
        assert en != fr
        assert "Invalid" in en
        assert "Identifiants" in fr or "invalides" in fr

    def test_extending_with_new_locale(self) -> None:
        # Add German as a custom locale
        from neozen.core.i18n import Translator

        custom = Translator(default_locale="en")
        custom.add_catalog(
            "de",
            Catalog({
                "email.password_reset.subject": (
                    "{app_name}-Passwort zur\u00fccksetzen"
                ),
            }),
        )

        msg = custom.gettext(
            "email.password_reset.subject",
            locale="de",
            app_name="Test",
        )
        assert "Test-Passwort" in msg
