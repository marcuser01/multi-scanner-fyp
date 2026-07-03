import uuid
import asyncio
import time
import shutil
import os
import zipfile
import json
import traceback
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Optional

from fastapi import APIRouter, UploadFile, File, BackgroundTasks, Depends, HTTPException, Form
from sqlalchemy.orm import Session

from app.core.database import get_db, SessionLocal
from app.models.database import Scan, CorrelatedIssue, AuditLog, User
from app.services.scanner_srv import SemgrepScanner, TrivyScanner, ZapScanner
from app.services.parser_srv import normalize_semgrep_results, normalize_trivy_results, normalize_zap_results
from app.services.heuristic_srv import run_heuristic_deduplication
from app.services.rag_srv import RAGEngine
from app.core.config import settings
from app.api.dependencies import require_admin_or_analyst, get_current_user

router = APIRouter()
rag_service = RAGEngine()

def verify_and_pin_url(url: str) -> Optional[str]:
    """
    SSRF Protection with TOCTOU / DNS-Rebinding mitigation.
    Resolves the hostname immediately, validates the IP, and rewrites
    the URL using the raw IP address to pin the destination downstream.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return None
        
        # 1. Resolve the hostname immediately (Time of Check)
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # 2. Check against private/loopback allocations
        if ip_obj.is_private or ip_obj.is_loopback:
            return None
        
        # 3. Reconstruct the netloc using the literal IP to pin it (Time of Use)
        netloc = ip
        if parsed.port:
            netloc = f"{ip}:{parsed.port}"
        if parsed.username:
            auth = parsed.username
            if parsed.password:
                auth = f"{auth}:{parsed.password}"
            netloc = f"{auth}@{netloc}"
            
        # Re-assemble URL with the hardcoded IP address
        pinned_parsed = parsed._replace(netloc=netloc)
        return pinned_parsed.geturl()
    except Exception:
        return None

def process_and_extract_zip(file_obj, zip_path, extract_path):
    """Safely handles blocking file I/O and zip extraction in a worker thread"""
    with open(zip_path, "wb") as buffer:
        shutil.copyfileobj(file_obj, buffer)
        
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        MAX_UNCOMPRESSED_SIZE = 500 * 1024 * 1024
        uncompressed_size = 0
        for member in zip_ref.infolist():
            uncompressed_size += member.file_size
            if uncompressed_size > MAX_UNCOMPRESSED_SIZE:
                raise HTTPException(400, "Zip Bomb Blocked: Exceeds 500MB Limit")
            target_path = os.path.abspath(os.path.join(extract_path, member.filename))
            if not target_path.startswith(os.path.abspath(extract_path)):
                raise HTTPException(400, "Zip Slip Blocked: Path traversal detected.")
        zip_ref.extractall(extract_path)

@router.get("")
async def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role == "ADMIN":
        return db.query(Scan).order_by(Scan.scanned_at.desc()).all()
    return db.query(Scan).filter(Scan.owner_id == current_user.id).order_by(Scan.scanned_at.desc()).all()

@router.post("")
async def create_scan(
    background_tasks: BackgroundTasks,
    task_name: str = Form("New Scan Task"),
    task_description: str = Form(""),
    scanLevel: str = Form("standard"),
    scanners_json: str = Form("{}"),
    target_url: str = Form(""),
    dast_mode: str = Form("baseline"),
    file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # BUSINESS LOGIC GUARD: Prevent API Bypass Privilege Escalation
    if current_user.role == "DEVELOPER" and dast_mode == "full":
        db.add(AuditLog(user_id=current_user.id, action="UNAUTHORIZED_DAST_ATTEMPT", target=target_url))
        db.commit()
        raise HTTPException(status_code=403, detail="Developers are restricted from running Intrusive DAST attacks.")

    scan_id = str(uuid.uuid4())
    selected_scanners = json.loads(scanners_json)

    if target_url:
        target_url = target_url.strip()
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        
        pinned_url = await asyncio.to_thread(verify_and_pin_url, target_url)
        if not pinned_url:
            raise HTTPException(status_code=400, detail="Invalid URL or internal/private IPs are restricted.")
        target_url = pinned_url

    upload_path = os.path.join(settings.UPLOAD_DIR, scan_id)
    os.makedirs(upload_path, exist_ok=True)
    extract_path = os.path.join(upload_path, "src")

    if selected_scanners.get("sast") or selected_scanners.get("sca"):
        if not file:
            raise HTTPException(status_code=400, detail="ZIP file is required for SAST/SCA.")
        zip_path = os.path.join(upload_path, "source.zip")
        try:
            await asyncio.to_thread(process_and_extract_zip, file.file, zip_path, extract_path)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid ZIP: {str(e)}")

    new_scan = Scan(
        id=scan_id,
        task_name=task_name,
        task_description=task_description,
        scan_level=scanLevel,
        status="running",
        owner_id=current_user.id,
        scanners_json=selected_scanners,
        target_url=target_url if selected_scanners.get("dast") else None,
        dast_mode=dast_mode if selected_scanners.get("dast") else None
    )
    db.add(new_scan)
    db.add(AuditLog(user_id=current_user.id, action="STARTED_SCAN", target=scan_id))
    db.commit()

    background_tasks.add_task(run_multi_scanner_pipeline, scan_id, extract_path, target_url, scanLevel, selected_scanners, dast_mode)
    return {"scan_id": scan_id, "status": "running"}

@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if current_user.role != "ADMIN" and scan.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return {"id": scan.id, "status": scan.status, "total_issues": scan.total_issues}

async def run_multi_scanner_pipeline(scan_id: str, src_path: str, target_url: str, scan_level: str, scanners: dict, dast_mode: str):
    # 1. Closed, short-lived transaction to clear stale entries
    db = SessionLocal()
    try:
        db.query(CorrelatedIssue).filter(CorrelatedIssue.scan_id == scan_id).delete()
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[ORCHESTRATOR] Error flushing tables: {e}")
    finally:
        db.close()

    # 2. SLOW WINDOW: No open DB connection is held while running background subprocesses!
    all_raw_findings = []
    if scan_level == "quick": sast_configs = ["p/default"]
    elif scan_level == "standard": sast_configs = ["p/default", "p/owasp-top-ten"]
    else: sast_configs = ["p/security-audit", "p/secrets", "p/default"]

    if scanners.get("sast"):
        try:
            raw_sast = await asyncio.to_thread(SemgrepScanner.execute, scan_id, src_path, sast_configs)
            if raw_sast and isinstance(raw_sast, dict):
                all_raw_findings.extend(normalize_semgrep_results(raw_sast, scan_id))
        except Exception as e: 
            print(f"[PIPELINE ERROR] SAST failed: {e}")

    if scanners.get("sca"):
        try:
            raw_sca = await asyncio.to_thread(TrivyScanner.execute, scan_id, src_path)
            if raw_sca and isinstance(raw_sca, dict):
                all_raw_findings.extend(normalize_trivy_results(raw_sca, scan_id))
        except Exception as e: 
            print(f"[PIPELINE ERROR] SCA failed: {e}")

    if scanners.get("dast") and target_url:
        try:
            raw_dast = await asyncio.to_thread(ZapScanner.execute, scan_id, target_url, dast_mode)
            if raw_dast and isinstance(raw_dast, dict):
                all_raw_findings.extend(normalize_zap_results(raw_dast, scan_id))
        except Exception as e: 
            print(f"[PIPELINE ERROR] DAST failed: {e}")

    # 3. Closed, short-lived transaction to run heuristics & deduplication
    db = SessionLocal()
    has_issues = False
    owner_id = None
    try:
        if not all_raw_findings:
            raise Exception("All selected scanners failed to produce results or timed out.")
        
        run_heuristic_deduplication(scan_id, all_raw_findings, db)

        issues = db.query(CorrelatedIssue).filter(CorrelatedIssue.scan_id == scan_id).all()
        has_issues = len(issues) > 0
        critical_count = len([i for i in issues if i.primary_severity == 'CRITICAL'])
        high_count = len([i for i in issues if i.primary_severity == 'HIGH'])

        scan_record = db.query(Scan).filter(Scan.id == scan_id).first()
        owner_id = scan_record.owner_id if scan_record else None
        
        db.query(Scan).filter(Scan.id == scan_id).update({
            "status": "analyzing", "total_issues": len(issues),
            "critical_count": critical_count, "high_count": high_count
        })
        db.add(AuditLog(user_id=owner_id, action="SCAN_COMPLETE", target=scan_id, details=f"Found {len(issues)} issues."))
        db.commit()
    except Exception as e:
        db.rollback()
        error_msg = str(e)
        # Old feature preservation: Maintain human-friendly string matching context for raw execution runtime limits
        if "Docker Daemon" in error_msg or "Docker Proxy" in error_msg:
            error_msg = "Docker environment inaccessible. DAST scanning skipped."
        
        scan_record = db.query(Scan).filter(Scan.id == scan_id).first()
        db.query(Scan).filter(Scan.id == scan_id).update({"status": "failed", "error_message": error_msg})
        db.add(AuditLog(user_id=scan_record.owner_id if scan_record else None, action="SCAN_FAILED", target=scan_id, details=error_msg))
        db.commit()
        db.close()
        traceback.print_exc()
        return
    finally:
        db.close()

    # 4. Trigger AI Generation (RAG queries DB internally and closes connections cleanly)
    if has_issues:
        print(f"[ORCHESTRATOR] 🤖 Auto-generating AI Executive Summary...")
        try:
            await rag_service.generate_scan_summary(scan_id)
            
            db = SessionLocal()
            db.add(AuditLog(user_id=owner_id, action="AI_SUMMARY_GENERATED", target=scan_id))
            db.commit()
            db.close()
        except Exception as ai_e:
            print(f"[ORCHESTRATOR] ⚠️ AI Summary failed: {ai_e}")
            db = SessionLocal()
            db.add(AuditLog(user_id=owner_id, action="AI_SUMMARY_FAILED", target=scan_id, details=str(ai_e)))
            db.commit()
            db.close()

    # 5. Closed, short-lived transaction to mark finished
    db = SessionLocal()
    try:
        db.query(Scan).filter(Scan.id == scan_id).update({"status": "completed"})
        db.commit()
        print(f"[ORCHESTRATOR] 🎉 Pipeline Complete. Scan {scan_id[:8]} finished.")
    except Exception as e:
        db.rollback()
        print(f"[ORCHESTRATOR] Error finalizing scan status: {e}")
    finally:
        db.close()