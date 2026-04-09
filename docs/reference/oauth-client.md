# OAuth Client Reference

**Module**: `neozen.core.oauth_client`

The OAuth client handles social login flows with external providers
(Google, GitHub, etc.).

## OAuthClientService

```python
from neozen.core.oauth_client.service import OAuthClientService
from neozen.core.oauth_client.providers.google import GoogleProvider
from neozen.core.oauth_client.providers.github import GitHubProvider

service = OAuthClientService(
    social_account_repository=social_account_repo,
    state_repository=state_repo,
    http_client=httpx.AsyncClient(),
)

# Register providers
service.register_provider(GoogleProvider(config=google_config, http_client=http))
service.register_provider(GitHubProvider(config=github_config, http_client=http))
```

### Methods

| Method | Description |
|--------|-------------|
| `begin_authorization(provider_id, redirect_uri)` | Start OAuth flow, returns URL + state |
| `handle_callback(provider_id, code, state, redirect_uri)` | Exchange code for tokens + user info |
| `create_social_account(subject_id, callback_result)` | Link account to subject |
| `get_or_create_subject_id(callback_result)` | Find existing subject by social account |
| `update_tokens(subject_id, provider_id, callback_result)` | Update stored tokens |
| `refresh_access_token(provider_id, refresh_token)` | Refresh an expired access token |
| `unlink_account(subject_id, provider_id)` | Remove social account link |
| `get_linked_accounts(subject_id)` | List linked social accounts |

## Authorization Flow

### 1. Begin Authorization

```python
result = service.begin_authorization("google", redirect_uri="https://app.com/callback")
# result.authorization_url -- redirect the user here
# result.state             -- stored for CSRF validation
```

### 2. Handle Callback

```python
callback = await service.handle_callback(
    provider_id="google",
    code=request.query_params["code"],
    state=request.query_params["state"],
    redirect_uri="https://app.com/callback",
)
# callback.user_info  -- OAuthUserInfo (email, name, avatar, etc.)
# callback.tokens     -- OAuthTokens (access_token, refresh_token, etc.)
```

### 3. Link or Create Account

```python
subject_id, is_new = await service.get_or_create_subject_id(callback)

if is_new:
    # Create a new user in your app
    subject_id = await create_user(callback.user_info)
    await service.create_social_account(subject_id, callback)
else:
    # Update tokens for existing user
    await service.update_tokens(subject_id, "google", callback)
```

## Token Refresh

When an access token expires:

```python
new_tokens = await service.refresh_access_token("google", old_refresh_token)
# new_tokens.access_token   -- fresh access token
# new_tokens.refresh_token  -- new or original refresh token
# new_tokens.expires_in     -- seconds until expiration
```

## Provider Configuration

```python
from neozen.core.oauth_client.models import OAuthProviderConfig

config = OAuthProviderConfig(
    provider_id="google",
    display_name="Google",
    authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
    token_endpoint="https://oauth2.googleapis.com/token",
    userinfo_endpoint="https://www.googleapis.com/oauth2/v3/userinfo",
    client_id="your-client-id",
    client_secret="your-client-secret",
    scopes=["openid", "email", "profile"],
    use_pkce=True,
)
```

## Built-in Providers

| Provider | Module | Scopes |
|----------|--------|--------|
| Google | `neozen.core.oauth_client.providers.google` | openid, email, profile |
| GitHub | `neozen.core.oauth_client.providers.github` | user:email, read:user |

## OAuthUserInfo

Returned from `handle_callback()`:

| Field | Type | Description |
|-------|------|-------------|
| `provider_id` | str | Provider name |
| `provider_user_id` | str | User ID at provider |
| `email` | str \| None | Email address |
| `email_verified` | bool | Whether email is verified |
| `display_name` | str \| None | User's display name |
| `avatar_url` | str \| None | Profile picture URL |
| `raw_data` | dict | Full provider response |
