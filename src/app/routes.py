"""Application routes."""

from litestar import get
from litestar.response import Response


@get("/")
async def index() -> dict:
    """Home page."""
    return {"message": "Welcome!"}


@get("/health")
async def health() -> dict:
    """Health check endpoint."""
    return {"status": "ok"}


routes = [index, health]
