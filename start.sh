#!/bin/bash
# Start the Flask app with gunicorn in the background
gunicorn --bind 0.0.0.0:$PORT web333:app &

# Start the transaction listener
python transaction_listener.py
