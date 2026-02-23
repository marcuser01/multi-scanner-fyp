import uuid
import time
import shutil
import os
import zipfile
from fastapi import APIRouter, UploadFile, File, BackgroundTasks, Depends, HTTPException, Form
from sqlalchemy.orm import Session

from app.core.database import get_db, SessionLocal
from app.models.database import Scan, Finding
from app.services.scanner_srv import SemgrepScanner
from app.services.parser_srv import normalize_semgrep_results
from app.core.config import settings

router = APIRouter()

# FIX: Added GET method to handle dashboard listing
@router.get("")
async def list_scans(db: Session = Depends(get_db)):
    scans_list = db.query(Scan).order_by(Scan.scanned_at.desc()).all()
    # Convert SQLAlchemy objects to dicts to ensure JSON serializable
    return scans_list

@router.post("")
async def create_scan(
    background_tasks: BackgroundTasks,
    task_name: str = Form("New Scan Task"), # NEW
    task_description: str = Form(""), # NEW
    config: str = Form("auto"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    scan_id = str(uuid.uuid4())
    upload_path = os.path.join(settings.UPLOAD_DIR, scan_id)
    os.makedirs(upload_path, exist_ok=True)
    
    zip_path = os.path.join(upload_path, "source.zip")
    try:
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        extract_path = os.path.join(upload_path, "src")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to process ZIP: {str(e)}")

    new_scan = Scan(
        id=scan_id, 
        task_name=task_name, # NEW
        task_description=task_description, # NEW
        status="running", 
        config_profile=config, 
        scanner="semgrep"
    )
    db.add(new_scan)
    db.commit()

    background_tasks.add_task(run_and_parse_scan, scan_id, extract_path, config)
    
    return {"scan_id": scan_id, "status": "running"}

@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"id": scan.id, "status": scan.status, "total_findings": scan.total_findings}

async def run_and_parse_scan(scan_id: str, src_path: str, config: str):
    print(f"\n[DEBUG] Starting background task for scan: {scan_id}")
    # 1. Verification Step: List files in the source path
    if os.path.exists(src_path):
        files = os.listdir(src_path)
        print(f"[DEBUG] Files extracted for scan: {files}")
    else:
        print(f"[DEBUG] ERROR: Source path {src_path} does not exist!")
    time.sleep(1)
    db = SessionLocal()
    try:
        raw_json = SemgrepScanner.execute(scan_id, src_path, config)
        
        if raw_json and "results" in raw_json:
            findings_count = len(raw_json["results"])
            print(f"[DEBUG] Semgrep found {findings_count} raw findings.")
            
            normalized, summary = normalize_semgrep_results(raw_json, scan_id)
            
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "completed"
                scan.total_findings = len(normalized)
                scan.rules_run = summary["rules_run"]
                scan.scan_duration = int(summary["duration"])
                
                # Clear any existing findings (just in case)
                db.query(Finding).filter(Finding.scan_id == scan_id).delete()
                
                for f_data in normalized:
                    db.add(Finding(**f_data))
                
                db.commit()
                print(f"[DEBUG] Database updated. {len(normalized)} findings saved.")
        else:
            print("[DEBUG] Scan completed with 0 results or failed.")
            db.query(Scan).filter(Scan.id == scan_id).update({"status": "completed", "total_findings": 0})
            db.commit()
    except Exception as e:
        print(f"[DEBUG] CRITICAL ERROR: {str(e)}")
        db.query(Scan).filter(Scan.id == scan_id).update({"status": "failed"})
        db.commit()
    finally:
        print(f"[DEBUG] Successful and no issues!")
        db.close()