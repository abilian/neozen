"""Serve command - run the NeoZen demo application."""

from __future__ import annotations

import argparse


def run(args: argparse.Namespace) -> int:
    """Run the demo application server."""
    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn is required to run the demo server.")
        print("Install it with: pip install neozen[demo]")
        return 1

    print(f"Starting NeoZen demo server at http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop.")
    print()

    uvicorn.run(
        "neozen.demo.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )

    return 0
