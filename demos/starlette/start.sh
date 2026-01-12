#!/usr/bin/env bash
# Start the NeoZen Starlette demo application.
#
# Usage:
#   ./start.sh              # Start on default port 8000
#   ./start.sh --reload     # Start with auto-reload for development
#   ./start.sh --port 8080  # Start on custom port

set -e

# Change to the script's directory
cd "$(dirname "$0")"

# Add project root to PYTHONPATH
PROJECT_ROOT="$(cd ../.. && pwd)"
export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH:-}"

# Default values
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
RELOAD=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            HOST="$2"
            shift 2
            ;;
        --port|-p)
            PORT="$2"
            shift 2
            ;;
        --reload|-r)
            RELOAD="--reload"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--host HOST] [--port PORT] [--reload]"
            exit 1
            ;;
    esac
done

echo "Starting NeoZen Starlette demo at http://${HOST}:${PORT}"
echo "Press Ctrl+C to stop."
echo

exec uvicorn app:app --host "$HOST" --port "$PORT" $RELOAD
