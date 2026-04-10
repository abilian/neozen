"""Framework-agnostic internationalization for NeoZen.

Provides a simple catalog-based translation system without depending
on Flask-Babel or other framework-specific tools.

Usage:
    from neozen.core.i18n import Translator, Catalog, negotiate_locale

    # Build catalogs
    en = Catalog({"welcome": "Welcome", "logout": "Log out"})
    fr = Catalog({"welcome": "Bienvenue", "logout": "Déconnexion"})

    translator = Translator(default_locale="en")
    translator.add_catalog("en", en)
    translator.add_catalog("fr", fr)

    # Translate
    msg = translator.gettext("welcome", locale="fr")  # "Bienvenue"

    # Locale negotiation (RFC 4647)
    locale = negotiate_locale(
        ui_locales=None,
        user_preference="fr-CA",
        accept_language="en-US,fr;q=0.9",
        available=["en", "fr"],
        default="en",
    )

For email templates and other built-in NeoZen strings, the
`builtin_translator` provides English and French translations of
the catalog used by `neozen.core.email.templates`.
"""

from __future__ import annotations

from neozen.core.i18n.builtin import builtin_translator
from neozen.core.i18n.locale import negotiate_locale, parse_accept_language
from neozen.core.i18n.translator import Catalog, Translator

__all__ = [
    "Catalog",
    "Translator",
    "builtin_translator",
    "negotiate_locale",
    "parse_accept_language",
]
