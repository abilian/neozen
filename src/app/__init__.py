"""neozen - Litestar application."""

from litestar import Litestar

from .routes import routes


def create_app() -> Litestar:
    """Application factory."""
    return Litestar(
        route_handlers=routes,
        debug=True,
    )


app = create_app()
