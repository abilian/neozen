# Litestar Integration

NeoZen provides a Litestar plugin at `neozen.ext.litestar` with
middleware-based session management, guards, and async helpers.

## Setup

```python
from litestar import Litestar, Request, get
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.stores.memory import MemoryStore
from neozen.ext.litestar import (
    NeoZenConfig, NeoZenPlugin,
    get_current_user, is_authenticated,
    login_required, login_user, logout_user,
)
from neozen.storage.sqlalchemy import SessionServiceFactory, create_subject_loader

session_service = SessionServiceFactory(session_factory, SECRET_KEY)

neozen_config = NeoZenConfig(
    session_service=session_service,
    subject_loader=create_subject_loader(session_factory),
    cookie_secure=False,  # Set True in production
    login_path="/login",
)

session_config = ServerSideSessionConfig(key="session", max_age=86400 * 7)

app = Litestar(
    route_handlers=[...],
    plugins=[NeoZenPlugin(neozen_config)],
    middleware=[session_config.middleware],
    stores={"sessions": MemoryStore()},
)
```

## Login

```python
from litestar import post
from litestar.response import Redirect

@post("/login")
async def login_submit(request: Request) -> Response:
    form = await request.form()
    email = str(form.get("email", "")).lower()
    password = str(form.get("password", ""))

    async with session_factory() as db_session:
        repo = SubjectRepository(session=db_session)
        try:
            subject = await repo.get_one_by(email=email)
            valid, _ = hasher.verify_and_update(password, subject.hashed_password)
            if valid:
                response = Redirect(path="/dashboard")
                await login_user(request, response, subject)
                return response
        except DoesNotExist:
            pass

    flash(request, "Invalid email or password", "error")
    return render_template(request, "login.html", {"current_user": None})
```

## Protected Routes

```python
@get("/dashboard", guards=[login_required()])
async def dashboard(request: Request) -> Response:
    user = await get_current_user(request)
    return render_template(request, "dashboard.html", {"current_user": user})
```

## Admin Guard

```python
from litestar.connection import ASGIConnection
from litestar.handlers import BaseRouteHandler
from litestar.exceptions import NotAuthorizedException

def admin_required():
    async def guard(connection: ASGIConnection, _: BaseRouteHandler) -> None:
        user = await get_current_user(connection)
        if not user:
            raise NotAuthorizedException("Admin access required")
        roles = await get_subject_roles(session_factory, user.id)
        if "admin" not in roles:
            raise NotAuthorizedException("Admin access required")
    return guard

@get("/admin", guards=[login_required(), admin_required()])
async def admin_dashboard(request: Request) -> Response:
    ...
```

## Logout

```python
@post("/logout")
async def logout_submit(request: Request) -> Response:
    response = Redirect(path="/")
    await logout_user(request, response)
    return response
```

## CSRF Protection

NeoZen's session cookie is `SameSite=Lax`, which stops most cross-site form posts but not all of them (older browsers, `SameSite=None` deployments). The plugin doesn't own your login, logout or settings forms, so turn on Litestar's CSRF middleware:

```python
from litestar.config.csrf import CSRFConfig

app = Litestar(..., csrf_config=CSRFConfig(secret=SECRET_KEY, cookie_secure=True))
```

With Litestar's template engine, put `{{ csrf_input | safe }}` in each form; HTMX and JavaScript send the token in the `x-csrftoken` header instead. The OAuth consent form is the exception: NeoZen protects it itself, with a `consent_token` (see [Consent Form](oidc.md#consent-form)).

## Direct Factor Wiring

If you own your User model and don't want to use NeoZen's
middleware, you can wire factors directly:

```python
from neozen.core.factors.password import create_password_factor
from neozen.core.identifiers.email import create_email_identifier

# In your login handler:
identifier = create_email_identifier(my_user_repo_adapter)
factor = create_password_factor(identifier, my_user_repo_adapter, hasher)
user = await factor.authenticate({"identifier": email, "password": password})
```

See [Bring Your Own Model](bring-your-own-model.md) for details.

## Demo Application

A complete Litestar demo is at `demos/litestar/` in the repository.
