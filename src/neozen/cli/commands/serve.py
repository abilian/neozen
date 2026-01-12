"""Serve command - run the NeoZen demo application."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def run(args: argparse.Namespace) -> int:
    """Run the demo application server."""
    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn is required to run the demo server.")
        print("Install it with: pip install neozen[demo]")
        return 1

    demo_type = getattr(args, "demo", "starlette")

    # Map demo types to their module paths
    demo_modules = {
        "starlette": "demos.starlette.app:app",
    }

    if demo_type not in demo_modules:
        print(f"Error: Unknown demo type '{demo_type}'")
        print(f"Available demos: {', '.join(demo_modules.keys())}")
        return 1

    # Ensure the project root is in the Python path for demos
    project_root = Path(__file__).parent.parent.parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    app_path = demo_modules[demo_type]

    print(f"Starting NeoZen {demo_type} demo at http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop.")
    print()

    uvicorn.run(
        app_path,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )

    return 0
