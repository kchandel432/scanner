import shutil
from pathlib import Path

def cleanup_project():
    """
    Removes unnecessary files and folders to make the project production-ready.
    """
    # Determine project root (assuming script is in scripts/ or root)
    current_path = Path(__file__).resolve()
    if current_path.parent.name == 'scripts':
        project_root = current_path.parent.parent
    else:
        project_root = current_path.parent

    print(f"Cleaning up project at: {project_root}")

    files_to_delete = [
        "backend/main.py",       # Redundant: backend/app/main.py is the correct entry point
        "frontend/app.py",       # Legacy: Streamlit app replaced by Jinja2/FastAPI
    ]

    folders_to_delete = [
        "frontend/src",          # Legacy: React source
        "frontend/public",       # Legacy: React assets
    ]

    # Remove files
    for file_rel_path in files_to_delete:
        file_path = project_root / file_rel_path
        if file_path.exists():
            file_path.unlink()
            print(f"✅ Deleted file: {file_rel_path}")

    # Remove folders
    for folder_rel_path in folders_to_delete:
        folder_path = project_root / folder_rel_path
        if folder_path.exists() and folder_path.is_dir():
            shutil.rmtree(folder_path)
            print(f"✅ Deleted folder: {folder_rel_path}")

if __name__ == "__main__":
    cleanup_project()