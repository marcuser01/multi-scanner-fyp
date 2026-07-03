import os
import shutil
import subprocess
import sys

# Ensure absolute paths
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BACKEND_DIR)

from app.core.database import init_db, SessionLocal
from app.core.config import settings
from app.models.database import User
from app.core.security import get_password_hash

def force_delete(path):
    if not path or not os.path.exists(path):
        return
    try:
        if os.path.isfile(path):
            os.remove(path)
        else:
            shutil.rmtree(path)
        print(f"  [+] Destroyed: {path}")
    except Exception as e:
        print(f"  [!] Failed to delete {path}. Error: {e}")

def main():
    print("=== AI Triage Platform: Hard Reset ===")
    
    # 1. Resolve exact DB path safely
    raw_db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    if not os.path.isabs(raw_db_path):
        db_path = os.path.abspath(os.path.join(BACKEND_DIR, raw_db_path.lstrip("./")))
    else:
        db_path = raw_db_path
        
    print(f"\n1. Wiping SQLite Database at: {db_path}")
    force_delete(db_path)
    
    print("\n2. Wiping ChromaDB Vector Store...")
    force_delete(os.path.abspath(settings.CHROMA_PATH))
    
    print("\n3. Wiping Temporary Uploads...")
    force_delete(os.path.abspath(settings.UPLOAD_DIR))
    
    print("\n4. Rebuilding Folder Structure...")
    os.makedirs(os.path.abspath(settings.UPLOAD_DIR), exist_ok=True)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    print("  [+] Directories created successfully.")
    
    print("\n5. Initializing Database Schema...")
    init_db()
    print("  [+] SQLite tables created perfectly.")

    print("\n6. Seeding Vector Knowledge Base...")
    script_path = os.path.abspath(os.path.join(BACKEND_DIR, "..", "scripts", "seed_kb.py"))
    if os.path.exists(script_path):
        subprocess.run([sys.executable, script_path])
    else:
        print(f"  [!] Could not find seed script at {script_path}.")

    print("\n=== Reset Complete! You can now start the backend and login. ===")

if __name__ == "__main__":
    main()