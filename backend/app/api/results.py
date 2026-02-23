from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.database import Finding
from app.services.rag_srv import RAGEngine

router = APIRouter()
rag_service = RAGEngine()

@router.get("/{scan_id}/findings")
async def list_findings(scan_id: str, db: Session = Depends(get_db)):
    return db.query(Finding).filter(Finding.scan_id == scan_id).all()

@router.post("/{finding_id}/ai-triage")
async def trigger_triage(finding_id: int, db: Session = Depends(get_db)):
    # Check if finding exists
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # FIX: Pass the finding_id and the db session as required by RAGEngine
    try:
        insight = await rag_service.triage_finding(finding_id, db)
        
        # Persistent storage of the analysis
        finding.ai_analysis = insight # Ensure this matches your model (ai_insight or ai_analysis)
        db.commit()
        
        return {"status": "success", "insight": insight}
    except Exception as e:
        print(f"RAG Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))