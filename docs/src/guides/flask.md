# Flask Integration

NeoZen provides a Flask extension at `neozen.ext.flask` that handles session management, login/logout helpers, and route protection.

## Setup

```python
from flask import Flask
from neozen.ext.flask import NeoZen, current_user, login_required, login_user, logout_user
from neozen.storage.sqlalchemy import SessionServiceFactory, create_subject_loader

app = Flask(__name__)
app.secret_key = "change-me-in-production"

# Database (see Installation guide)
engine, session_factory = create_database("data/app.db")

# Session service
session_service = SessionServiceFactory(session_factory, app.secret_key)

# NeoZen extension
neozen = NeoZen(
    app,
    session_service=session_service,
    subject_loader=create_subject_loader(session_factory),
)
```

## Login

```python
from neozen.ext.flask import UserMixin

class User(UserMixin):
    def __init__(self, id, email, hashed_password, **kwargs):
        self.id = id
        self.email = email
        self.hashed_password = hashed_password

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form["email"].lower()
        password = request.form["password"]

        user = User.get_by_email(email)
        if user and user.check_password(password):
            login_user(user, remember=True)
            return redirect(url_for("dashboard"))

        flash("Invalid email or password", "error")

    return render_template("login.html")
```

## Protected Routes

```python
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)
```

The decorators work on `async def` views too. For a sensitive action, `fresh_login_required` also wants the session to have started recently (15 minutes by default, `max_age=` to change it), and sends an older one to sign in again:

```python
@app.route("/settings/password", methods=["POST"])
@fresh_login_required
def change_password():
    ...
```

API clients get the same JSON from every adapter: `{"error": "unauthorized", "detail": ...}` with a 401, and `{"error": "forbidden", "detail": ...}` with a 403 (with Flask, `roles_required` and `permissions_required` call `abort(403)`, so your 403 error handler decides).

## Logout

```python
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))
```

## CSRF Protection

NeoZen's session cookie is `SameSite=Lax`, which stops most cross-site form posts but not all of them (older browsers, `SameSite=None` deployments). The extension doesn't own your login, logout or settings forms, so protect them with your framework's CSRF support. For Flask, that's [Flask-WTF](https://flask-wtf.readthedocs.io/en/stable/csrf/):

```python
from flask_wtf import CSRFProtect

CSRFProtect(app)  # every POST must now carry the token
```

```html
<form method="post" action="/login">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  ...
</form>
```

The OAuth consent form is the exception: NeoZen protects it itself, with a `consent_token` (see [Consent Form](oidc.md#consent-form)).

## Security Headers

NeoZen doesn't set headers on your app's responses. Behind HTTPS, send at least `Strict-Transport-Security` (usually from the reverse proxy), and `Content-Security-Policy: frame-ancestors 'none'` on the sign-in and account pages, so another site can't frame them (clickjacking). A full Content Security Policy depends on your templates and scripts.

## Admin Guard

```python
from functools import wraps
from neozen.storage.sqlalchemy import get_subject_roles

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.has_role("admin"):
            flash("Admin access required", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated

@app.route("/admin")
@admin_required
def admin_dashboard():
    return render_template("admin/dashboard.html")
```

## Demo Application

A complete Flask demo is available at `demos/flask/` in the repository, including:

- Registration with first-user-gets-admin logic
- Login with password, magic link, TOTP 2FA
- Social login (Google, GitHub)
- WebAuthn/Passkeys
- Admin console (user, role, session management)
