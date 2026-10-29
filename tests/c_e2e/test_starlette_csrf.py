"""The Starlette demo's CSRF middleware."""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from demos.starlette.app import CSRFMiddleware, csrf_token


async def page(request: Request) -> PlainTextResponse:
    return PlainTextResponse(csrf_token(request))


async def submit(request: Request) -> PlainTextResponse:
    form = await request.form()
    return PlainTextResponse(f"got {form['name']}")


def _client() -> TestClient:
    app = Starlette(
        routes=[
            Route("/form", page),
            Route("/form", submit, methods=["POST"]),
            Route("/api/form", submit, methods=["POST"]),
        ],
        middleware=[
            Middleware(SessionMiddleware, secret_key="k"),
            Middleware(CSRFMiddleware),
        ],
    )
    return TestClient(app)


def test_post_without_token_is_refused() -> None:
    with _client() as client:
        client.get("/form")
        assert client.post("/form", data={"name": "x"}).status_code == 403


def test_post_with_token_reaches_the_handler() -> None:
    with _client() as client:
        token = client.get("/form").text
        response = client.post("/form", data={"name": "x", "csrf_token": token})
    assert response.text == "got x"


def test_json_api_is_left_out() -> None:
    with _client() as client:
        assert client.post("/api/form", data={"name": "x"}).text == "got x"
