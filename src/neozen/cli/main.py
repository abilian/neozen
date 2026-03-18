"""Main CLI entry point for NeoZen.

Provides commands for:
- subject: Manage subjects (create, list)
- client: Manage OAuth clients (create, list)
"""

from __future__ import annotations

import argparse
import sys

from neozen.cli.commands import client, role, subject


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser."""
    parser = argparse.ArgumentParser(
        prog="neozen",
        description="NeoZen Authentication CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  neozen subject create -e user@example.com -p secret
  neozen subject list
  neozen client create --name myapp
  neozen client list
  neozen role init
  neozen role create -n editor -p post:read -p post:write
  neozen role assign -s user123 -r editor
  neozen role show-subject user123
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

    # Role command
    role_parser = subparsers.add_parser(
        "role",
        help="Manage authorization roles",
        description="Create and manage RBAC roles and assignments.",
    )
    role_subparsers = role_parser.add_subparsers(
        dest="subcommand",
        title="subcommands",
    )

    # role create
    role_create = role_subparsers.add_parser(
        "create",
        help="Create a new role",
    )
    role_create.add_argument(
        "--name",
        "-n",
        required=True,
        help="Role name",
    )
    role_create.add_argument(
        "--permission",
        "-p",
        action="append",
        dest="permissions",
        help="Permission string (e.g., 'user:read'). Can be repeated.",
    )
    role_create.add_argument(
        "--description",
        "-d",
        help="Role description",
    )
    role_create.set_defaults(func=role.create)

    # role list
    role_list = role_subparsers.add_parser(
        "list",
        help="List all roles",
    )
    role_list.add_argument(
        "--format",
        "-f",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    role_list.set_defaults(func=role.list_roles)

    # role delete
    role_delete = role_subparsers.add_parser(
        "delete",
        help="Delete a role",
    )
    role_delete.add_argument(
        "name",
        help="Role name to delete",
    )
    role_delete.set_defaults(func=role.delete)

    # role assign
    role_assign = role_subparsers.add_parser(
        "assign",
        help="Assign a role to a subject",
    )
    role_assign.add_argument(
        "--subject",
        "-s",
        required=True,
        dest="subject_id",
        help="Subject ID to assign role to",
    )
    role_assign.add_argument(
        "--role",
        "-r",
        required=True,
        help="Role name to assign",
    )
    role_assign.add_argument(
        "--scope-type",
        choices=["global", "team", "resource"],
        default="global",
        help="Scope type (default: global)",
    )
    role_assign.add_argument(
        "--scope-id",
        help="Scope ID (required for team/resource scopes)",
    )
    role_assign.set_defaults(func=role.assign)

    # role revoke
    role_revoke = role_subparsers.add_parser(
        "revoke",
        help="Revoke a role from a subject",
    )
    role_revoke.add_argument(
        "--subject",
        "-s",
        required=True,
        dest="subject_id",
        help="Subject ID to revoke role from",
    )
    role_revoke.add_argument(
        "--role",
        "-r",
        required=True,
        help="Role name to revoke",
    )
    role_revoke.add_argument(
        "--scope-type",
        choices=["global", "team", "resource"],
        default="global",
        help="Scope type (default: global)",
    )
    role_revoke.add_argument(
        "--scope-id",
        help="Scope ID (required for team/resource scopes)",
    )
    role_revoke.set_defaults(func=role.revoke)

    # role show-subject
    role_show = role_subparsers.add_parser(
        "show-subject",
        help="Show roles for a subject",
    )
    role_show.add_argument(
        "subject_id",
        help="Subject ID to show roles for",
    )
    role_show.add_argument(
        "--format",
        "-f",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    role_show.set_defaults(func=role.show_subject)

    # role init
    role_init = role_subparsers.add_parser(
        "init",
        help="Initialize built-in roles",
    )
    role_init.set_defaults(func=role.init)

    return parser


def main(args: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = create_parser()
    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        return 0

    # Handle commands with subcommands
    if parsed.command in ("subject", "client", "role") and not getattr(
        parsed, "subcommand", None
    ):
        # Print help for the specific command
        if parsed.command == "subject":
            parser.parse_args(["subject", "--help"])
        elif parsed.command == "client":
            parser.parse_args(["client", "--help"])
        elif parsed.command == "role":
            parser.parse_args(["role", "--help"])
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
