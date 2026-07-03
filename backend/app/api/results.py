import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload

from app.api.dependencies import get_current_user
from app.core.database import get_db
from app.models.database import AuditLog, CorrelatedIssue, Scan, User
from app.services.rag_srv import RAGEngine
from app.services.report_srv import generate_pdf_report

router = APIRouter()
rag_service = RAGEngine()

# Pydantic Schema for Workflow State mutations
class IssueUpdateRequest(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None

@router.get("/{scan_id}/correlated")
async def get_correlated_scan_data(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # IDOR PREVENTION: Only the owner or an ADMIN can view this scan's results
    if current_user.role != "ADMIN" and scan.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized access to scan results.")
        
    issues = db.query(CorrelatedIssue)\
               .options(joinedload(CorrelatedIssue.findings))\
               .filter(CorrelatedIssue.scan_id == scan_id).all()
               
    return {"scan": scan, "issues": issues}

@router.post("/{issue_id}/ai-triage")
async def trigger_triage(issue_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    issue = db.query(CorrelatedIssue).filter(CorrelatedIssue.id == issue_id).first()
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
        
    scan = db.query(Scan).filter(Scan.id == issue.scan_id).first()
    if current_user.role != "ADMIN" and scan.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    try:
        # DB session is safely isolated and terminated within triage_issue
        insight = await rag_service.triage_issue(issue_id)
        issue.ai_insight = insight
        
        # AUDIT LOG: Track on-demand AI triage
        db.add(AuditLog(user_id=current_user.id, action="AI_TRIAGE_FINDING", target=str(issue_id), details=f"Triaged issue: {issue.title}"))
        db.commit()
        return {"status": "success", "insight": insight}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{scan_id}/generate-report")
async def generate_executive_report(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan: 
        raise HTTPException(status_code=404, detail="Scan not found")
    if current_user.role != "ADMIN" and scan.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized")
        
    try:
        # Decouple the long-running summary generation transaction
        summary = await rag_service.generate_scan_summary(scan_id)
        db.add(AuditLog(user_id=current_user.id, action="AI_SCAN_SUMMARY", target=scan_id))
        db.commit()
        return {"summary": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{scan_id}/report/pdf")
async def get_pdf_report(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # IDOR Check: Ensure user owns this report or is Admin
    if current_user.role != "ADMIN" and scan.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized to download this report.")
        
    issues = db.query(CorrelatedIssue)\
               .options(joinedload(CorrelatedIssue.findings))\
               .filter(CorrelatedIssue.scan_id == scan_id).all()

    # Generate PDF (Saves secure, non-IDOR-bypassable assets dynamically)
    pdf_path = generate_pdf_report(scan, issues)
    
    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="Failed to locate generated asset.")
        
    # AUDIT LOG: Record report export
    db.add(AuditLog(user_id=current_user.id, action="DOWNLOADED_PDF_REPORT", target=scan_id))
    db.commit()

    return FileResponse(pdf_path, media_type="application/pdf", filename=os.path.basename(pdf_path))

@router.patch("/{issue_id}/workflow")
async def update_issue_workflow(issue_id: int, req: IssueUpdateRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    issue = db.query(CorrelatedIssue).filter(CorrelatedIssue.id == issue_id).first()
    if not issue: 
        raise HTTPException(status_code=404, detail="Issue not found")
    
    # Fetch parent scan to verify resource tenancy and access rights
    scan = db.query(Scan).filter(Scan.id == issue.scan_id).first()
    if current_user.role != "ADMIN" and scan.owner_id != current_user.id:
         raise HTTPException(status_code=403, detail="Forbidden")

    if req.status is not None:
        issue.status = req.status
    if req.assignee is not None:
        issue.assignee = req.assignee

    db.commit()
    return {"status": "success", "issue_status": issue.status, "assignee": issue.assignee}