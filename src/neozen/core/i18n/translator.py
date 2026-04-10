"""Translation catalog and translator."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Catalog:
    """A message catalog mapping message IDs to translated strings.

    Catalogs are immutable -- create a new one to update.
    """

    messages: dict[str, str] = field(default_factory=dict)

    def get(self, message_id: str) -> str | None:
        """Look up a message. Returns None if not found."""
        return self.messages.get(message_id)

    def __contains__(self, message_id: str) -> bool:
        return message_id in self.messages


class Translator:
    """Routes translation requests to the appropriate catalog.

    Translators look up messages in catalogs by locale, with fallback
    to a regional parent (e.g., fr-CA -> fr) and finally to the
    default locale.

    Example:
        translator = Translator(default_locale="en")
        translator.add_catalog("en", Catalog({"hi": "Hello"}))
        translator.add_catalog("fr", Catalog({"hi": "Bonjour"}))

        translator.gettext("hi", locale="fr")     # "Bonjour"
        translator.gettext("hi", locale="fr-CA")  # "Bonjour" (fallback)
        translator.gettext("hi", locale="de")     # "Hello" (default)
        translator.gettext("missing", locale="fr") # "missing" (id as-is)
    """

    def __init__(self, default_locale: str = "en") -> None:
        self.default_locale = default_locale
        self._catalogs: dict[str, Catalog] = {}

    def add_catalog(self, locale: str, catalog: Catalog) -> None:
        """Register a catalog for a locale."""
        self._catalogs[locale.lower()] = catalog

    def merge_catalog(self, locale: str, catalog: Catalog) -> None:
        """Merge messages into an existing catalog (or create one)."""
        existing = self._catalogs.get(locale.lower())
        if existing is None:
            self._catalogs[locale.lower()] = catalog
            return
        merged = {**existing.messages, **catalog.messages}
        self._catalogs[locale.lower()] = Catalog(messages=merged)

    def has_locale(self, locale: str) -> bool:
        return locale.lower() in self._catalogs

    def available_locales(self) -> list[str]:
        return list(self._catalogs.keys())

    def gettext(
        self,
        message_id: str,
        *,
        locale: str | None = None,
        **kwargs: object,
    ) -> str:
        """Translate a message ID for the given locale.

        If the message is not found, returns the message ID unchanged.
        Supports keyword substitution via `str.format()`.

        Args:
            message_id: The message identifier to translate.
            locale: The target locale (e.g., "en", "fr", "fr-CA").
                If None, uses the default locale.
            **kwargs: Substitution values for `{placeholder}` in the message.
        """
        target = (locale or self.default_locale).lower()
        catalog = self._lookup_catalog(target)

        if catalog is not None:
            text = catalog.get(message_id)
            if text is not None:
                return text.format(**kwargs) if kwargs else text

        # Fallback to default locale
        if target != self.default_locale.lower():
            default_catalog = self._catalogs.get(self.default_locale.lower())
            if default_catalog is not None:
                text = default_catalog.get(message_id)
                if text is not None:
                    return text.format(**kwargs) if kwargs else text

        # Last resort: return the message ID itself, with substitutions
        return message_id.format(**kwargs) if kwargs else message_id

    def _lookup_catalog(self, locale: str) -> Catalog | None:
        """Find a catalog for the locale, walking up regional fallbacks.

        For example, "fr-CA" tries "fr-ca" first, then "fr".
        """
        if locale in self._catalogs:
            return self._catalogs[locale]

        # Strip region: fr-CA -> fr
        if "-" in locale:
            base = locale.split("-", 1)[0]
            if base in self._catalogs:
                return self._catalogs[base]

        return None


__all__ = ["Catalog", "Translator"]
