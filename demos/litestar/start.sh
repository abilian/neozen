#!/bin/bash
# Start the Litestar demo server
uvicorn demos.litestar.app:app --reload --host 0.0.0.0 --port 8001
