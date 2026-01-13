"""Mixins and base classes for Flask authentication."""

from __future__ import annotations


class AnonymousUser:
    """Represents an unauthenticated user.

    This class is returned by `current_user` when no user is logged in.
    It provides a consistent interface for checking authentication status.
    """

    @property
    def is_authenticated(self) -> bool:
        """Return False for anonymous users."""
        return False

    @property
    def is_anonymous(self) -> bool:
        """Return True for anonymous users."""
        return True

    @property
    def is_active(self) -> bool:
        """Return False for anonymous users."""
        return False

    @property
    def id(self) -> None:
        """Return None for anonymous users."""
        return None

    def __repr__(self) -> str:
        return "<AnonymousUser>"

    def __bool__(self) -> bool:
        """Anonymous users are falsy."""
        return False


class UserMixin:
    """Mixin that adds authentication properties to Subject models.

    Add this mixin to your Subject model to ensure compatibility with
    NeoZen's Flask extension.

    Example:
        class User(UserMixin, Base):
            __tablename__ = "users"
            id: Mapped[str] = mapped_column(primary_key=True)
            email: Mapped[str]
            # ... other fields
    """

    @property
    def is_authenticated(self) -> bool:
        """Return True for authenticated users."""
        return True

    @property
    def is_anonymous(self) -> bool:
        """Return False for authenticated users."""
        return False

    def __bool__(self) -> bool:
        """Authenticated users are truthy."""
        return True


__all__ = ["AnonymousUser", "UserMixin"]
