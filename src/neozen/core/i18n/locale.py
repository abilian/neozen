"""Locale negotiation following RFC 4647 (Matching of Language Tags)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LanguageTag:
    """A language tag with optional quality value (RFC 7231)."""

    tag: str
    quality: float = 1.0


def parse_accept_language(header: str | None) -> list[LanguageTag]:
    """Parse an Accept-Language header into a sorted list of language tags.

    Tags are sorted by quality (descending), preserving order for ties.

    Examples:
        >>> parse_accept_language("en-US,fr;q=0.9,de;q=0.8")
        [LanguageTag(tag='en-us', quality=1.0),
         LanguageTag(tag='fr', quality=0.9),
         LanguageTag(tag='de', quality=0.8)]
    """
    if not header:
        return []

    tags: list[LanguageTag] = []
    for part in header.split(","):
        part = part.strip()
        if not part:
            continue

        # Parse "tag;q=X.Y"
        if ";" in part:
            tag_part, _, params = part.partition(";")
            quality = 1.0
            for param in params.split(";"):
                param = param.strip()
                if param.startswith("q="):
                    try:
                        quality = float(param[2:])
                    except ValueError:
                        quality = 1.0
            tags.append(LanguageTag(tag=tag_part.strip().lower(), quality=quality))
        else:
            tags.append(LanguageTag(tag=part.lower(), quality=1.0))

    # Stable sort by quality descending
    return sorted(tags, key=lambda t: -t.quality)


def _match_locale(requested: str, available: list[str]) -> str | None:
    """Match a single locale against the available list.

    Tries exact match first, then language-only match (e.g., "fr-CA" -> "fr").
    Returns the matched available locale or None.
    """
    requested_lower = requested.lower()
    available_lower = [a.lower() for a in available]

    # Exact match
    if requested_lower in available_lower:
        idx = available_lower.index(requested_lower)
        return available[idx]

    # Language-only match (drop region)
    if "-" in requested_lower:
        base = requested_lower.split("-", 1)[0]
        if base in available_lower:
            idx = available_lower.index(base)
            return available[idx]

    # Reverse: maybe the available list has a more-specific tag
    for i, avail in enumerate(available_lower):
        if "-" in avail and avail.split("-", 1)[0] == requested_lower:
            return available[i]

    return None


def _try_ui_locales(
    ui_locales: str | list[str] | None,
    available: list[str],
) -> str | None:
    if not ui_locales:
        return None
    ui_list = ui_locales.split() if isinstance(ui_locales, str) else list(ui_locales)
    for locale in ui_list:
        match = _match_locale(locale, available)
        if match:
            return match
    return None


def _try_accept_language(
    accept_language: str | None,
    available: list[str],
) -> str | None:
    if not accept_language:
        return None
    for tag in parse_accept_language(accept_language):
        match = _match_locale(tag.tag, available)
        if match:
            return match
    return None


def negotiate_locale(
    *,
    ui_locales: str | list[str] | None = None,
    user_preference: str | None = None,
    accept_language: str | None = None,
    available: list[str],
    default: str = "en",
) -> str:
    """Negotiate a locale from multiple sources, in priority order.

    Priority (per OIDC and most i18n libs):
    1. `ui_locales` -- explicit request parameter (e.g., from OIDC auth request)
    2. `user_preference` -- stored user preference
    3. `accept_language` -- Accept-Language header
    4. `default` -- fallback

    Args:
        ui_locales: Space-separated string or list of preferred locales.
        user_preference: Stored locale preference.
        accept_language: Accept-Language header value.
        available: List of locales the application supports.
        default: Fallback locale.

    Returns:
        The first matching locale from `available`, or `default`.
    """
    if not available:
        return default

    match = _try_ui_locales(ui_locales, available)
    if match:
        return match

    if user_preference:
        match = _match_locale(user_preference, available)
        if match:
            return match

    match = _try_accept_language(accept_language, available)
    if match:
        return match

    if default in available:
        return default
    return available[0]


__all__ = [
    "LanguageTag",
    "negotiate_locale",
    "parse_accept_language",
]
