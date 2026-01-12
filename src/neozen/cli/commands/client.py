"""OAuth client management commands."""

from __future__ import annotations

import argparse
import json
import secrets


def create(args: argparse.Namespace) -> int:
    """Create a new OAuth client."""
    name = args.name
    redirect_uris = args.redirect_uris or []
    is_confidential = args.confidential

    # Generate client ID (always)
    client_id = f"nz_client_{secrets.token_hex(8)}"

    # Generate client secret (only for confidential clients)
    client_secret = None
    if is_confidential:
        client_secret = f"nz_secret_{secrets.token_urlsafe(32)}"

    print("OAuth client created successfully!")
    print()
    print(f"  Name:         {name}")
    print(f"  Client ID:    {client_id}")
    if client_secret:
        print(f"  Client Secret: {client_secret}")
        print()
        print("  IMPORTANT: Save the client secret now - it cannot be recovered!")
    print(f"  Type:         {'Confidential' if is_confidential else 'Public'}")
    if redirect_uris:
        print("  Redirect URIs:")
        for uri in redirect_uris:
            print(f"    - {uri}")
    print()
    print(
        "Note: This is a demo command. In production, clients would be "
        "stored in a database."
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
