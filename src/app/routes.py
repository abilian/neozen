"""Application routes."""

from __future__ import annotations

from litestar import get


@get("/")
def index() -> dict:
    """Home page."""
    return {"message": "Welcome!"}


@get("/health")
def health() -> dict:
    """Health check endpoint."""
    return {"status": "ok"}


routes = [index, health]
