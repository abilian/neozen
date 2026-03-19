# NeoZen Demo Applications

This directory contains demo applications showcasing NeoZen authentication and authorization features across different Python web frameworks.

## Available Demos

| Framework | Port | Description |
|-----------|------|-------------|
| **Starlette** | 8000 | ASGI framework with middleware-based auth |
| **Litestar** | 8001 | Modern ASGI framework with plugin-based auth |
| **Flask** | 8002 | WSGI framework with Flask-Login style API |

## Features Demonstrated

All demos include:

- **User Registration** - Create new accounts with email/password
- **User Login/Logout** - Session-based authentication
- **Protected Routes** - Login-required dashboard
- **Flash Messages** - Success/error notifications
- **Role-Based Access** - First user gets admin privileges
- **Role Badges** - Dashboard displays user roles
- **Admin Panel** - Visible only to admin users
- **JSON API** - REST endpoints for programmatic access

## Running the Demos

### From Project Root

```bash
# Starlette demo
./demos/starlette/start.sh

# Litestar demo
./demos/litestar/start.sh

# Flask demo
./demos/flask/start.sh
```

### With uvicorn/flask directly

```bash
# Starlette (port 8000)
uvicorn demos.starlette.app:app --reload --port 8000

# Litestar (port 8001)
uvicorn demos.litestar.app:app --reload --port 8001

# Flask (port 8002)
FLASK_APP=demos.flask.app:app flask run --port 8002
```

## Testing the Authorization Features

1. **Clear existing data** (optional):
   ```bash
   rm demos/starlette/data/neozen.db
   ```

2. **Start a demo** and open in browser

3. **Register the first user** - This user automatically receives the `admin` role

4. **Check the dashboard** - You should see:
   - Your roles displayed as badges (admin, user)
   - An "Admin Panel" section (admin-only content)

5. **Register a second user** - This user only gets the `user` role

6. **Log in as second user** - The Admin Panel is not visible

## Directory Structure

```
demos/
├── README.md           # This file
├── starlette/
│   ├── app.py          # Main application
│   ├── start.sh        # Start script
│   ├── templates/      # Jinja2 templates
│   └── data/           # SQLite database (created on first run)
├── litestar/
│   ├── app.py          # Main application
│   ├── start.sh        # Start script
│   └── templates/      # Jinja2 templates
└── flask/
    ├── app.py          # Main application
    ├── start.sh        # Start script
    └── templates/      # Jinja2 templates
```

## API Endpoints

All demos expose these JSON API endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/register` | Register new user |
| POST | `/api/login` | Login and get session |
| POST | `/api/logout` | Logout (requires auth) |
| GET | `/api/me` | Get current user info (requires auth) |

### Example API Usage

```bash
# Register
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Login
curl -X POST http://localhost:8000/api/login \
  -c cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Get current user
curl http://localhost:8000/api/me -b cookies.txt
```

## Implementation Notes

### In-Memory Storage

All demos use in-memory dictionaries for user and session storage. Data is lost when the server restarts. This is intentional for demo simplicity.

### First-User Admin Pattern

The first registered user automatically receives admin privileges:

```python
is_first_user = len(users_db) == 0
roles = ["admin", "user"] if is_first_user else ["user"]
```

### Role-Based UI

Templates check user roles for conditional content:

```html
{% if 'admin' in current_user.roles %}
<article class="admin-panel">
    <!-- Admin-only content -->
</article>
{% endif %}
```

## See Also

- [NeoZen Admin UI](../src/neozen/admin/) - Full-featured admin interface
- [Framework Extensions](../src/neozen/ext/) - Integration code for each framework
