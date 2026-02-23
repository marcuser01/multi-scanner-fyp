from sqlalchemy import Column, Integer, String, JSON, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func  # Add this for automatic timestamps
import datetime

Base = declarative_base()

class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    # Changed to func.now() for Python 3.13 compatibility
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True)
    task_name = Column(String, nullable=True) # NEW
    task_description = Column(Text, nullable=True) # NEW
    project_id = Column(Integer, ForeignKey("projects.id"))
    scanner = Column(String)
    config_profile = Column(String)
    status = Column(String)
    
    total_findings = Column(Integer, default=0)
    scan_duration = Column(Integer)
    rules_run = Column(Integer)
    # Changed to func.now()
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())
    
    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id"))
    
    title = Column(String)
    severity = Column(String)
    file_path = Column(String)
    line_number = Column(Integer)
    description = Column(Text)
    
    cwe = Column(String)
    owasp = Column(String)
    owasp_full = Column(String, nullable=True)
    vulnerability_class = Column(String)
    
    raw_json = Column(JSON)
    ai_insight = Column(Text, nullable=True)
    
    scan = relationship("Scan", back_populates="findings")