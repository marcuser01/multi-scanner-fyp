import chromadb
from openai import OpenAI
from app.core.config import settings
from app.models.database import Finding, Scan
from sqlalchemy.orm import Session

class RAGEngine:
    def __init__(self):
        # Initialize Local ChromaDB
        self.client = chromadb.PersistentClient(path=settings.CHROMA_PATH)
        self.collection = self.client.get_or_create_collection(name="security_kb")

    async def triage_finding(self, finding_id: int, db: Session):
        # 1. Fetch Finding and Parent Scan for Context
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            return "Finding not found in database."
            
        scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()
        
        # 2. Load API Key
        try:
            with open(settings.LLM_KEY_PATH, "r") as f:
                api_key = f.read().strip()
        except FileNotFoundError:
            return "Error: API Key file not found. Please set it in Settings."

        # 3. Targeted Retrieval (CWE)
        target_id = f"cwe/{finding.cwe}.md"
        context_docs = ""
        
        try:
            res = self.collection.get(ids=[target_id])
            if res['documents']:
                context_docs = res['documents'][0]
        except:
            # Fallback to semantic search
            search = self.collection.query(query_texts=[finding.description], n_results=1)
            context_docs = search['documents'][0][0] if search['documents'] else "General security principles."

        # 4. OpenRouter Integration
        # FIX: Move extra_headers from the constructor to the .create method
        client = OpenAI(
            base_url=settings.OPENROUTER_BASE_URL,
            api_key=api_key,
        )
        
        # Updated Prompt inside rag_srv.py
        prompt = f"""
        [STRICT INSTRUCTIONS]
        You are a Senior Security Architect. You must analyze the following finding using ONLY the provided CWE STANDARDS and APP CONTEXT. 
        If information is missing, explicitly state "Information not provided in scan results."
        DO NOT hallucinate external libraries or features not mentioned in the context.

        [STEP 1: INFORMATION & CONTEXT SUMMARY]
        - Target Application: {scan.task_name if scan else 'Unnamed'}
        - Application Purpose: {scan.task_description if scan else 'General software'}
        - Detected Vulnerability: {finding.title}
        - Security Standard: {finding.cwe.upper() if finding.cwe else 'N/A'} ({finding.vulnerability_class})
        - Precise Location: File '{finding.file_path}' at Line {finding.line_number}
        
        [STEP 2: CWE KNOWLEDGE BASE GROUNDING]
        {context_docs if context_docs else "No specific CWE markdown found. Use official OWASP/CWE general principles for " + finding.vulnerability_class}

        [REQUIRED OUTPUT TASKS]
        1. Contextual Assessment: Based on the "Application Purpose", how severe is this specific finding for this app?
        2. Business Impact: Explain to a non-technical owner why they should pay to fix this.
        3. Prioritized Remediation: 3 clear steps for the developer.
        4. Secure Code Example: Provide a Python/Javascript fix that resolves the '{finding.title}' issue.
        
        Answer in structured clean markdown.
        """

        try:
            response = client.chat.completions.create(
                model=settings.LLM_MODEL,
                messages=[{"role": "user", "content": prompt}],
                # FIX: Pass headers here instead of in OpenAI()
                extra_headers={
                    "HTTP-Referer": "http://localhost:5173", 
                    "X-Title": "AI-Vulnerability-Triage"
                }
            )
            return response.choices[0].message.content
        except Exception as e:
            if "429" in str(e):
                return "Error: Rate limit reached."
            return f"AI Service Error: {str(e)}"