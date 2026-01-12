"""Subject management commands."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from neozen.cli.database import DatabaseContext, get_database_url


async def _create_subject(
    session: AsyncSession,
    email: str,
    password: str,
    username: str | None,
) -> dict:
    """Create a new subject in the database."""
    from pwdlib import PasswordHash

    from neozen.storage import DoesNotExist
    from neozen.storage.sqlalchemy import SubjectRepository

    storage = SubjectRepository(session=session)

    # Check if email already exists
    try:
        await storage.get_one_by(email=email.lower())
        raise ValueError(f"Email '{email}' is already registered")
    except DoesNotExist:
        pass

    # Check if username already exists (if provided)
    if username:
        try:
            await storage.get_one_by(username=username.lower())
            raise ValueError(f"Username '{username}' is already taken")
        except DoesNotExist:
            pass

    # Hash password
    hasher = PasswordHash.recommended()
    hashed_password = hasher.hash(password)

    # Generate unique ID
    subject_id = f"subj_{secrets.token_hex(12)}"

    # Create subject
    subject = await storage.create(
        id=subject_id,
        email=email.lower(),
        username=username.lower() if username else None,
        hashed_password=hashed_password,
        is_active=True,
        is_verified=False,
    )

    return {
        "id": subject.id,
        "email": subject.email,
        "username": subject.username,
        "is_active": subject.is_active,
        "is_verified": subject.is_verified,
    }


async def _list_subjects(session: AsyncSession, output_format: str) -> list[dict]:
    """List all subjects from the database."""
    from neozen.storage.sqlalchemy import Subject

    result = await session.execute(select(Subject).order_by(Subject.created_at.desc()))
    subjects = result.scalars().all()

    return [
        {
            "id": s.id,
            "email": s.email,
            "username": s.username,
            "is_active": s.is_active,
            "is_verified": s.is_verified,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in subjects
    ]


def create(args: argparse.Namespace) -> int:
    """Create a new subject."""
    email = args.email
    password = args.password
    username = args.username

    # Prompt for password if not provided
    if not password:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Error: Passwords do not match.")
            return 1

    if not password:
        print("Error: Password is required.")
        return 1

    # Validate email format
    if "@" not in email:
        print("Error: Invalid email format.")
        return 1

    async def run() -> int:
        db_url = get_database_url()
        async with DatabaseContext(db_url) as session:
            try:
                result = await _create_subject(session, email, password, username)
                print("Subject created successfully!")
                print(f"  ID:       {result['id']}")
                print(f"  Email:    {result['email']}")
                if result["username"]:
                    print(f"  Username: {result['username']}")
                print(f"  Active:   {result['is_active']}")
                print(f"  Verified: {result['is_verified']}")
                return 0
            except ValueError as e:
                print(f"Error: {e}")
                return 1

    return asyncio.run(run())


def list_subjects(args: argparse.Namespace) -> int:
    """List all subjects."""
    output_format = args.format

    async def run() -> int:
        db_url = get_database_url()
        async with DatabaseContext(db_url) as session:
            subjects = await _list_subjects(session, output_format)

            if output_format == "json":
                print(json.dumps({"subjects": subjects}, indent=2, default=str))
            else:
                print("Subjects")
                print("-" * 80)
                if not subjects:
                    print("(No subjects found)")
                else:
                    print(f"{'ID':<30} {'Email':<30} {'Username':<15} {'Active':<8}")
                    print("-" * 80)
                    for s in subjects:
                        username = s["username"] or "-"
                        active = "Yes" if s["is_active"] else "No"
                        print(
                            f"{s['id']:<30} {s['email']:<30} {username:<15} {active:<8}"
                        )
                print()
                print(f"Total: {len(subjects)} subject(s)")

            return 0

    return asyncio.run(run())
