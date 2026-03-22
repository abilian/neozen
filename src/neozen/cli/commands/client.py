"""OAuth client management commands."""

from __future__ import annotations

import argparse
import json
import secrets


def create(args: argparse.Namespace) -> int:
    """Create a new OAuth client."""
    name = args.name
    redirect_uris = args.redirect_uris or []
    client_type = "confidential" if args.confidential else "public"
    scopes = getattr(args, "scopes", None) or []
    grant_types = getattr(args, "grant_types", None) or [
        "authorization_code",
        "refresh_token",
    ]

    # Generate client ID
    client_id = secrets.token_hex(32)

    # Generate client secret (only for confidential clients)
    client_secret = None
    if client_type == "confidential":
        client_secret = secrets.token_urlsafe(48)

    print("OAuth client created successfully!")
    print()
    print(f"  Name:           {name}")
    print(f"  Client ID:      {client_id}")
    if client_secret:
        print(f"  Client Secret:  {client_secret}")
        print()
        print("  IMPORTANT: Save the client secret now - it cannot be recovered!")
    print(f"  Type:           {client_type}")
    if redirect_uris:
        print("  Redirect URIs:")
        for uri in redirect_uris:
            print(f"    - {uri}")
    if scopes:
        print(f"  Allowed Scopes: {' '.join(scopes)}")
    print(f"  Grant Types:    {' '.join(grant_types)}")
    print()
    print(
        "Note: This is a demo command. In production, use the database "
        "integration or API endpoints."
    )

    return 0


def list_clients(args: argparse.Namespace) -> int:
    """List all OAuth clients."""
    output_format = args.format

    if output_format == "json":
        print(
            json.dumps({
                "clients": [],
                "message": "Demo mode - no database configured",
            })
        )
    else:
        print("OAuth Clients")
        print("-" * 60)
        print("(No clients found - demo mode, no database configured)")
        print()
        print("Run 'neozen serve' to start the demo application,")
        print("then use the API to register clients.")

    return 0


def show(args: argparse.Namespace) -> int:
    """Show details of an OAuth client."""
    client_id = args.client_id

    print(f"Looking up client: {client_id}")
    print()
    print("(Demo mode - no database configured)")
    print("In production, this would show:")
    print("  - Client name")
    print("  - Client type (public/confidential)")
    print("  - Redirect URIs")
    print("  - Allowed scopes")
    print("  - Allowed grant types")
    print("  - Active status")
    print("  - Created/updated timestamps")

    return 0


def rotate_secret(args: argparse.Namespace) -> int:
    """Rotate a client's secret."""
    client_id = args.client_id

    # In production, this would call the ClientService
    new_secret = secrets.token_urlsafe(48)

    print(f"Rotated secret for client: {client_id}")
    print()
    print(f"  New Secret: {new_secret}")
    print()
    print("  IMPORTANT: Save the new secret now - it cannot be recovered!")
    print()
    print("(Demo mode - secret not persisted)")

    return 0


def deactivate(args: argparse.Namespace) -> int:
    """Deactivate an OAuth client."""
    client_id = args.client_id

    print(f"Deactivated client: {client_id}")
    print()
    print("The client can no longer authenticate or obtain tokens.")
    print("(Demo mode - not persisted)")

    return 0


def activate(args: argparse.Namespace) -> int:
    """Activate an OAuth client."""
    client_id = args.client_id

    print(f"Activated client: {client_id}")
    print()
    print("The client can now authenticate and obtain tokens.")
    print("(Demo mode - not persisted)")

    return 0
