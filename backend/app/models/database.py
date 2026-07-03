# backend/app/models/database.py
from sqlalchemy import Column, Integer, String, JSON, DateTime, ForeignKey, Text, Boolean # <-- FIX: Added Boolean here
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="DEVELOPER") # ADMIN, ANALYST, DEVELOPER
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())    
    scans = relationship("Scan", back_populates="owner")

class SystemConfig(Base):
    """Stores encrypted global API keys"""
    __tablename__ = "system_config"
    key_name = Column(String, primary_key=True)
    encrypted_value = Column(Text)
class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String)
    target = Column(String)
    details = Column(String, nullable=True)

class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Bi-directional relationship to Scans
    scans = relationship("Scan", back_populates="project")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    project = relationship("Project", back_populates="scans")
    owner = relationship("User", back_populates="scans")

    task_name = Column(String)
    task_description = Column(Text)
    scan_level = Column(String) # "quick", "standard", "deep"
    status = Column(String) # "running", "analyzing", "completed", "failed"
    error_message = Column(Text, nullable=True) # NEW: Explicit error tracking

    # NEW: Store scan-time parameters for detailed reporting
    scanners_json = Column(JSON, nullable=True) # Stores e.g. {"sast": true, "sca": true, "dast": false}
    target_url = Column(String, nullable=True)
    dast_mode = Column(String, nullable=True) # "baseline" or "full"

    # Statistics for the Dashboard
    total_issues = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)

    # Tier 2 RAG Summary
    executive_summary = Column(Text, nullable=True)
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())

    # Link to CorrelatedIssues
    correlated_issues = relationship("CorrelatedIssue", back_populates="scan", cascade="all, delete-orphan")

# THE HEURISTIC MERGING TABLE
class CorrelatedIssue(Base):
    __tablename__ = "correlated_issues"
    id = Column(Integer, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id"))

    title = Column(String)
    primary_severity = Column(String)
    cwe = Column(String, nullable=True)
    owasp = Column(String, nullable=True)

    # Workflow Management Fields
    status = Column(String, default="open") # "open", "remediated", "ignored"
    assignee = Column(String, nullable=True, default="Unassigned")

    # Micro-RAG stores its insight here
    ai_insight = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="correlated_issues")
    findings = relationship("NormalizedFinding", back_populates="issue", cascade="all, delete-orphan")

# STORES THE RAW EVIDENCE FROM TOOLS
class NormalizedFinding(Base):
    __tablename__ = "normalized_findings"
    id = Column(Integer, primary_key=True)
    issue_id = Column(Integer, ForeignKey("correlated_issues.id"))

    scanner_type = Column(String) # "SAST", "SCA", "DAST"
    vulnerability_id = Column(String) # CVE or CWE
    description = Column(Text)

    evidence = Column(JSON)
    issue = relationship("CorrelatedIssue", back_populates="findings")