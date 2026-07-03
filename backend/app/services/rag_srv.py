import chromadb
from openai import OpenAI
from app.core.config import settings
from app.models.database import Scan, CorrelatedIssue, SystemConfig
from app.core.database import SessionLocal
from app.core.security import decrypt_secret
from sqlalchemy.orm import Session, joinedload

class RAGEngine:
    def __init__(self):
        self.client = chromadb.PersistentClient(path=settings.CHROMA_PATH)
        self.collection = self.client.get_or_create_collection(name="security_kb")

    async def triage_issue(self, issue_id: int, db: Session = None):
        # Maintain backwards compatibility while supporting isolated local sessions
        is_local_session = db is None
        if is_local_session:
            db = SessionLocal()
            
        try:
            issue = db.query(CorrelatedIssue).options(joinedload(CorrelatedIssue.findings)).filter(CorrelatedIssue.id == issue_id).first()
            if not issue: 
                return "Issue not found."
            scan = db.query(Scan).filter(Scan.id == issue.scan_id).first()

            conf = db.query(SystemConfig).filter(SystemConfig.key_name == "OPENROUTER_API_KEY").first()
            if not conf: 
                return "Error: API Key not configured in System Settings. Please vault your key."
            api_key = decrypt_secret(conf.encrypted_value)

            context_docs = ""
            if issue.cwe:
                target_id = f"cwe/{issue.cwe.lower()}.md"
                try:
                    res = self.collection.get(ids=[target_id])
                    if res and res.get('documents') and len(res['documents']) > 0:
                        context_docs = res['documents'][0]
                except Exception: 
                    pass

            evidence_list = []
            for f in issue.findings:
                ev = f.evidence
                if 'file' in ev: evidence_list.append(f"File: {ev['file']} at Line {ev.get('line')}")
                if 'url' in ev: evidence_list.append(f"URL: {ev['url']} (Method: {ev.get('method')})")
                if 'package' in ev: evidence_list.append(f"Dependency: {ev['package']} (Version {ev.get('installed_version')})")
            evidence_str = "\n".join(evidence_list)

            # Deep copy variables needed for the prompt
            scan_desc = scan.task_description if scan else 'General software'
            issue_title = issue.title
            issue_severity = issue.primary_severity
        finally:
            # Only close if this engine opened it; don't close upstream-managed sessions
            if is_local_session:
                db.close()

        client = OpenAI(base_url=settings.LLM_BASE_URL, api_key=api_key)

        prompt = f"""
        You are a Senior Security Architect. Analyze this correlated issue.
        App Context: {scan_desc}
        Vulnerability: {issue_title} (Severity: {issue_severity})
        Locations Found:\n{evidence_str}

        [CWE STANDARDS]
        {context_docs if context_docs else "Use general OWASP security knowledge."}

        Provide a structured markdown response:
        1. Contextual Assessment (Why does this matter for THIS specific app?)
        2. Business Impact for management.
        3. Prioritized Remediation Steps.
        4. Code/Config Fix Example.
        """

        try:
            response = client.chat.completions.create(
                model=settings.LLM_MODEL,
                messages=[{"role": "user", "content": prompt}],
                extra_headers={"HTTP-Referer": "http://localhost", "X-Title": "AI-Triage"}
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error: AI Service failure. Details: {str(e)}"

    async def generate_scan_summary(self, scan_id: str, db: Session = None):
        is_local_session = db is None
        if is_local_session:
            db = SessionLocal()
            
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return "Error: Scan context not found."
                
            issues = db.query(CorrelatedIssue).options(joinedload(CorrelatedIssue.findings)).filter(CorrelatedIssue.scan_id == scan_id).all()

            total = len(issues)
            highs = len([i for i in issues if i.primary_severity in ['HIGH', 'CRITICAL']])

            issue_context_lines = []
            for i in issues:
                sources = list(set([f.scanner_type for f in i.findings]))
                issue_context_lines.append(f"- {i.primary_severity}: {i.title} (Found by: {', '.join(sources)})")
            top_issues_context = "\n".join(issue_context_lines[:15])

            conf = db.query(SystemConfig).filter(SystemConfig.key_name == "OPENROUTER_API_KEY").first()
            if not conf:
                err_config = "Error: API Key not configured in System Settings. Please vault your key."
                scan.executive_summary = err_config
                db.commit()
                return err_config
                
            api_key = decrypt_secret(conf.encrypted_value)
            
            # Deep Copy metadata for prompt
            task_name = scan.task_name
            task_description = scan.task_description
            scan_level = scan.scan_level
        finally:
            if is_local_session:
                db.close()

        prompt = f"""
        You are a Virtual CISO for an SME. Write a 3-paragraph executive security report for the recent scan.

        [APP CONTEXT]
        Name: {task_name}
        Description: {task_description}
        Scan Level: {scan_level}

        [SCAN METRICS]
        Total Vulnerabilities: {total}
        High/Critical Risks: {highs}

        [ISSUES FOUND]
        {top_issues_context if total > 0 else "No vulnerabilities were found!"}

        [TASK]
        Write a short summary answering:
        1. What is the overall security posture?
        2. What are the immediate business risks based on the specific vulnerabilities found?
        3. What should the engineering team prioritize?
        Format in clean markdown. Keep it professional and accessible for non-technical managers.
        """

        try:
            client = OpenAI(base_url=settings.LLM_BASE_URL, api_key=api_key)
            response = client.chat.completions.create(
                model=settings.LLM_MODEL,
                messages=[{"role": "user", "content": prompt}],
                extra_headers={"HTTP-Referer": "http://localhost", "X-Title": "AI-Triage"}
            )
            summary = response.choices[0].message.content
            
            # Save results in a dedicated short-lived write transaction
            write_db = SessionLocal()
            try:
                write_db.query(Scan).filter(Scan.id == scan_id).update({"executive_summary": summary})
                write_db.commit()
            finally:
                write_db.close()
                
            return summary
        except Exception as e:
            err_msg = f"Error: Failed to fetch summary. Details: {str(e)}"
            
            write_db = SessionLocal()
            try:
                write_db.query(Scan).filter(Scan.id == scan_id).update({"executive_summary": err_msg})
                write_db.commit()
            finally:
                write_db.close()
                
            return err_msg