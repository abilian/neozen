"""Built-in translation catalogs for NeoZen.

Provides English and French translations of the strings used by
`neozen.core.email.templates` and a few other user-facing messages.

Application code can extend this translator with additional locales:

    from neozen.core.i18n import builtin_translator, Catalog

    builtin_translator.add_catalog("de", Catalog({
        "email.password_reset.subject": "Setzen Sie Ihr {app_name}-Passwort zur\u00fccksetzen",
        # ...
    }))
"""

from __future__ import annotations

from neozen.core.i18n.translator import Catalog, Translator

# Message IDs follow a dotted hierarchy:
#   email.<template>.<part>
#   error.<code>
EN_MESSAGES: dict[str, str] = {
    # Password reset email
    "email.password_reset.subject": "Reset your {app_name} password",
    "email.password_reset.greeting": "Hello,",
    "email.password_reset.intro": ("We received a request to reset your password."),
    "email.password_reset.cta": "Click this link to set a new password:",
    "email.password_reset.expiry": "This link expires at {expiry}.",
    "email.password_reset.ignore": (
        "If you didn't request this, you can safely ignore this email."
    ),
    # Email verification
    "email.verification.subject": "Verify your {app_name} email",
    "email.verification.welcome": "Welcome to {app_name}!",
    "email.verification.cta": (
        "Please verify your email address by clicking this link:"
    ),
    # OTP code
    "email.otp.subject": "{app_name} verification code: {code}",
    "email.otp.intro": "Your {app_name} verification code is:",
    "email.otp.expiry": "This code expires in {lifetime}.",
    "email.otp.ignore": ("If you didn't request this, you can ignore this email."),
    # Account lockout
    "email.lockout.subject": "{app_name} account locked",
    "email.lockout.body": (
        "Your {app_name} account has been temporarily locked due to "
        "{failed_attempts} failed login attempts."
    ),
    "email.lockout.until": "Locked until: {until}",
    "email.lockout.advice": (
        "If this wasn't you, please reset your password as soon as the lockout expires."
    ),
    # Compromised password
    "email.compromised.subject": ("Action required: Update your {app_name} password"),
    "email.compromised.body": (
        "We detected that your {app_name} password appears in a known "
        "data breach. Your account has not been compromised, but you "
        "should change your password immediately."
    ),
    # Common error messages (used by validators / API responses)
    "error.invalid_credentials": "Invalid credentials.",
    "error.account_locked": "Account is locked.",
    "error.token_expired": "Token has expired.",
    "error.token_invalid": "Invalid or expired token.",
    "error.rate_limit_exceeded": "Too many requests. Please try again later.",
}

FR_MESSAGES: dict[str, str] = {
    # Password reset email
    "email.password_reset.subject": (
        "R\u00e9initialiser votre mot de passe {app_name}"
    ),
    "email.password_reset.greeting": "Bonjour,",
    "email.password_reset.intro": (
        "Nous avons re\u00e7u une demande de r\u00e9initialisation de votre "
        "mot de passe."
    ),
    "email.password_reset.cta": (
        "Cliquez sur ce lien pour d\u00e9finir un nouveau mot de passe :"
    ),
    "email.password_reset.expiry": "Ce lien expire le {expiry}.",
    "email.password_reset.ignore": (
        "Si vous n'avez pas fait cette demande, vous pouvez ignorer cet e-mail."
    ),
    # Email verification
    "email.verification.subject": "V\u00e9rifier votre e-mail {app_name}",
    "email.verification.welcome": "Bienvenue sur {app_name}\u00a0!",
    "email.verification.cta": (
        "Veuillez v\u00e9rifier votre adresse e-mail en cliquant sur ce lien :"
    ),
    # OTP
    "email.otp.subject": "Code de v\u00e9rification {app_name}\u00a0: {code}",
    "email.otp.intro": "Votre code de v\u00e9rification {app_name} est\u00a0:",
    "email.otp.expiry": "Ce code expire dans {lifetime}.",
    "email.otp.ignore": (
        "Si vous n'avez pas fait cette demande, vous pouvez ignorer cet e-mail."
    ),
    # Lockout
    "email.lockout.subject": "Compte {app_name} verrouill\u00e9",
    "email.lockout.body": (
        "Votre compte {app_name} a \u00e9t\u00e9 temporairement "
        "verrouill\u00e9 suite \u00e0 {failed_attempts} tentatives de "
        "connexion \u00e9chou\u00e9es."
    ),
    "email.lockout.until": "Verrouill\u00e9 jusqu'\u00e0\u00a0: {until}",
    "email.lockout.advice": (
        "Si ce n'\u00e9tait pas vous, veuillez r\u00e9initialiser votre "
        "mot de passe d\u00e8s la fin du verrouillage."
    ),
    # Compromised
    "email.compromised.subject": (
        "Action requise\u00a0: Mettez \u00e0 jour votre mot de passe {app_name}"
    ),
    "email.compromised.body": (
        "Nous avons d\u00e9tect\u00e9 que votre mot de passe {app_name} "
        "appara\u00eet dans une fuite de donn\u00e9es connue. Votre "
        "compte n'a pas \u00e9t\u00e9 compromis, mais vous devriez "
        "changer votre mot de passe imm\u00e9diatement."
    ),
    # Errors
    "error.invalid_credentials": "Identifiants invalides.",
    "error.account_locked": "Compte verrouill\u00e9.",
    "error.token_expired": "Le jeton a expir\u00e9.",
    "error.token_invalid": "Jeton invalide ou expir\u00e9.",
    "error.rate_limit_exceeded": (
        "Trop de requ\u00eates. Veuillez r\u00e9essayer plus tard."
    ),
}


def _build() -> Translator:
    translator = Translator(default_locale="en")
    translator.add_catalog("en", Catalog(messages=dict(EN_MESSAGES)))
    translator.add_catalog("fr", Catalog(messages=dict(FR_MESSAGES)))
    return translator


# Module-level singleton
builtin_translator: Translator = _build()


__all__ = [
    "EN_MESSAGES",
    "FR_MESSAGES",
    "builtin_translator",
]
