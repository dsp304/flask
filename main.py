"""
Main application entry point for Gunicorn / Procfile.
Delegates to app.py which defines all Task 1-4 routes, dashboard, and webhook listeners.
"""
import os
from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
