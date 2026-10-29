# Factor Protocols

Authentication factors are the pluggable methods NeoZen uses to verify
identity. Each factor implements one of three protocols depending on
its authentication flow.

## Protocol Hierarchy

```
FactorProtocol (base)
├── AuthenticatingFactorProtocol    -- single-step auth
├── ChallengingFactorProtocol       -- two-step challenge-response
└── EnrollableFactorProtocol        -- requires setup before use
```

## FactorProtocol (Base)

All factors share these properties and methods:

```python
class FactorProtocol(Protocol):
    @property
    def factor_id(self) -> str:
        """Unique ID: 'password', 'totp', 'magic_link', etc."""

    @property
    def display_name(self) -> str:
        """Human-readable: 'Password', 'Authenticator App', etc."""

    @property
    def factor_type(self) -> str:
        """'knowledge' | 'possession' | 'inherence'"""

    async def is_enrolled(self, subject_id: str) -> bool:
        """Whether the subject has this factor set up."""

    async def supports_subject(self, subject_id: str) -> bool:
        """Whether this factor can be used by the subject."""
```

## AuthenticatingFactorProtocol

Single-step factors implement this protocol: the credential exists before sign-in.

```python
class AuthenticatingFactorProtocol(FactorProtocol, Protocol):
    async def authenticate(
        self, subject_id: str, credential: Any, **kwargs
    ) -> bool:
        """Verify the credential. Returns True on success."""
```

**Used by**: `PasswordFactor`

## ChallengingFactorProtocol

For two-step flows where a challenge must be issued before
authentication can proceed.

```python
class ChallengingFactorProtocol(FactorProtocol, Protocol):
    async def begin_authentication(
        self, subject_id: str, **kwargs
    ) -> dict[str, Any]:
        """Issue a challenge. Returns challenge data."""

    async def complete_authentication(
        self, subject_id: str, response: Any, **kwargs
    ) -> bool:
        """Verify the response to the challenge."""
```

**Used by**: `MagicLinkFactor`, `WebAuthnFactor`

## EnrollableFactorProtocol

Factors that need explicit setup before use implement this protocol.

```python
class EnrollableFactorProtocol(FactorProtocol, Protocol):
    async def begin_enrollment(
        self, subject_id: str, **kwargs
    ) -> dict[str, Any]:
        """Start enrollment. Returns setup data (QR code, etc.)."""

    async def complete_enrollment(
        self, subject_id: str, verification: Any, **kwargs
    ) -> bool:
        """Verify and finalize enrollment."""

    async def unenroll(self, subject_id: str) -> None:
        """Remove this factor from a subject."""
```

**Used by**: `TOTPFactor`, `WebAuthnFactor`

!!! note "Multiple protocols"
    A factor can implement multiple protocols. `WebAuthnFactor`
    implements both `EnrollableFactorProtocol` (registration) and
    `ChallengingFactorProtocol` (authentication).

## Built-in Factors

| Factor | Protocols | Type | Description |
|--------|-----------|------|-------------|
| `PasswordFactor` | Authenticating | knowledge | Argon2id password verification |
| `TOTPFactor` | Enrollable | possession | Authenticator app codes |
| `WebAuthnFactor` | Enrollable + Challenging | possession | Passkeys / security keys |
| `MagicLinkFactor` | Challenging | possession | Passwordless email links |

## Factor Registry

Register factors for discovery:

```python
from neozen.core.factors.registry import FactorRegistry

registry = FactorRegistry()
registry.register(password_factor)
registry.register(totp_factor)
registry.register(magic_link_factor)

# Look up by ID
factor = registry.get("password")
challenging = registry.get_challenging_factor("magic_link")
```

## Creating a Custom Factor

```python
from neozen.core.factors.protocol import AuthenticatingFactorProtocol

class PINFactor:
    @property
    def factor_id(self) -> str:
        return "pin"

    @property
    def display_name(self) -> str:
        return "PIN Code"

    @property
    def factor_type(self) -> str:
        return "knowledge"

    async def is_enrolled(self, subject_id: str) -> bool:
        return await self.pin_repo.exists(subject_id=subject_id)

    async def supports_subject(self, subject_id: str) -> bool:
        return True

    async def authenticate(
        self, subject_id: str, credential: str, **kwargs
    ) -> bool:
        stored = await self.pin_repo.get_one_by(subject_id=subject_id)
        return hmac.compare_digest(credential, stored.pin_hash)
```
