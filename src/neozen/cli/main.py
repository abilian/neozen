"""Main CLI entry point for NeoZen.

Provides commands for:
- serve: Run the demo application
- subject: Manage subjects (create, list)
- client: Manage OAuth clients (create, list)
"""

from __future__ import annotations

import argparse
import sys

from neozen.cli.commands import client, serve, subject


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser."""
    parser = argparse.ArgumentParser(
        prog="neozen",
        description="NeoZen Authentication CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  neozen serve                         # Start the demo server
  neozen serve --port 8080             # Start on specific port
  neozen subject create -e user@example.com -p secret
  neozen subject list
  neozen client create --name myapp
  neozen client list
""",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="Available commands",
    )

    # Serve command
    serve_parser = subparsers.add_parser(
        "serve",
        help="Run the NeoZen demo application",
        description="Start the demo Starlette application with uvicorn.",
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )
    serve_parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=8000,
        help="Port to bind to (default: 8000)",
    )
    serve_parser.add_argument(
        "--reload",
        "-r",
        action="store_true",
        help="Enable auto-reload for development",
    )
    serve_parser.set_defaults(func=serve.run)

    # Subject command
    subject_parser = subparsers.add_parser(
        "subject",
        help="Manage subjects",
        description="Create and manage authentication subjects.",
    )
    subject_subparsers = subject_parser.add_subparsers(
        dest="subcommand",
        title="subcommands",
    )

    # subject create
    subject_create = subject_subparsers.add_parser(
        "create",
        help="Create a new subject",
    )
    subject_create.add_argument(
        "--email",
        "-e",
        required=True,
        help="Email address for the subject",
    )
    subject_create.add_argument(
        "--password",
        "-p",
        help="Password (will prompt if not provided)",
    )
    subject_create.add_argument(
        "--username",
        "-u",
        help="Optional username",
    )
    subject_create.set_defaults(func=subject.create)

    # subject list
    subject_list = subject_subparsers.add_parser(
        "list",
        help="List all subjects",
    )
    subject_list.add_argument(
        "--format",
        "-f",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    subject_list.set_defaults(func=subject.list_subjects)

    # Client command
    client_parser = subparsers.add_parser(
        "client",
        help="Manage OAuth clients",
        description="Create and manage OAuth 2.1 clients.",
    )
    client_subparsers = client_parser.add_subparsers(
        dest="subcommand",
        title="subcommands",
    )

    # client create
    client_create = client_subparsers.add_parser(
        "create",
        help="Create a new OAuth client",
    )
    client_create.add_argument(
        "--name",
        "-n",
        required=True,
        help="Client name",
    )
    client_create.add_argument(
        "--redirect-uri",
        "-r",
        action="append",
        dest="redirect_uris",
        help="Redirect URI (can be specified multiple times)",
    )
    client_create.add_argument(
        "--confidential",
        "-c",
        action="store_true",
        help="Create a confidential client (with client secret)",
    )
    client_create.set_defaults(func=client.create)

    # client list
    client_list = client_subparsers.add_parser(
        "list",
        help="List all OAuth clients",
    )
    client_list.add_argument(
        "--format",
        "-f",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    client_list.set_defaults(func=client.list_clients)

    return parser


def main(args: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = create_parser()
    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        return 0

    # Handle commands with subcommands
    if parsed.command in ("subject", "client") and not getattr(
        parsed, "subcommand", None
    ):
        # Print help for the specific command
        if parsed.command == "subject":
            parser.parse_args(["subject", "--help"])
        elif parsed.command == "client":
            parser.parse_args(["client", "--help"])
        return 0

    # Execute the command function
    if hasattr(parsed, "func"):
        try:
            return parsed.func(parsed)
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return 130
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
