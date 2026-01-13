#!/bin/bash
# Start the Flask demo server
export FLASK_APP=demos.flask.app:app
export FLASK_DEBUG=1
flask run --host 0.0.0.0 --port 8002
