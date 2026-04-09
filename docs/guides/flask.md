# Flask Integration

NeoZen provides a Flask extension at `neozen.ext.flask` that handles
session management, login/logout helpers, and route protection.

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

## Logout

```python
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))
```

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

A complete Flask demo is available at `demos/flask/` in the repository,
including:

- Registration with first-user-gets-admin logic
- Login with password, magic link, TOTP 2FA
- Social login (Google, GitHub)
- WebAuthn/Passkeys
- Admin console (user, role, session management)
