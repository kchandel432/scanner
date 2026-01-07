import os
from pathlib import Path

UPLOAD_DIR = Path("./data/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

def save_upload(file, filename: str) -> str:
    dest = UPLOAD_DIR / filename
    with open(dest, "wb") as f:
        f.write(file.file.read())
    return str(dest)
