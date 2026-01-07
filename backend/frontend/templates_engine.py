"""
Shared Jinja2 templates instance
"""
from fastapi.templating import Jinja2Templates
from pathlib import Path

# Setup templates directory
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "backend" / "frontend" / "templates"

# Create templates instance
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
