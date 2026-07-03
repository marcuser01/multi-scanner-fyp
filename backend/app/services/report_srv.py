import os
import markdown
import bleach
from datetime import datetime
from jinja2 import Template
from app.core.config import settings

def sanitize_ai_html(raw_html: str) -> str:
    """
    🛡️ Prevents LFI / Server-Side XSS via WeasyPrint.
    Strips out malicious tags like <style>, <link>, <iframe>, <script>, and <object>
    that an LLM might hallucinate or an attacker might inject.
    """
    allowed_tags = [
        'p', 'b', 'i', 'u', 'em', 'strong', 'a', 'ul', 'ol', 'li', 
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'code', 'pre', 'blockquote', 'br'
    ]
    return bleach.clean(raw_html, tags=allowed_tags, strip=True)

def generate_pdf_report(scan, issues):
    # Utilizing built-in Jinja2 'upper' filter tokens natively
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            @page { size: A4; margin: 20mm 15mm; @bottom-right { content: "Page " counter(page); font-size: 9pt; color: #64748b; } }
            body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #1e293b; line-height: 1.5; font-size: 11pt; }
            
            /* Cover Page & Headers */
            .cover { text-align: center; margin-top: 100px; page-break-after: always; }
            .cover h1 { font-size: 32pt; color: #0f172a; margin-bottom: 10px; }
            .cover h2 { font-size: 18pt; color: #3b82f6; font-weight: normal; margin-top: 0; }
            
            h2.section-header { font-size: 16pt; color: #0f172a; border-bottom: 2px solid #cbd5e1; padding-bottom: 5px; margin-top: 30px; page-break-after: avoid; }
            
            /* Metadata Grid */
            .meta-table { width: 100%; border-collapse: collapse; margin-top: 50px; margin-bottom: 30px; font-size: 10pt; }
            .meta-table th { background: #f8fafc; text-align: left; padding: 10px; border: 1px solid #e2e8f0; color: #475569; width: 30%; }
            .meta-table td { padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; }
            
            /* AI Summary */
            .ai-summary { background: #f0fdf4; border-left: 4px solid #22c55e; padding: 15px 20px; border-radius: 4px; margin-bottom: 30px; font-size: 10.5pt; text-align: justify; }
            
            /* Issue Cards */
            .issue-card { page-break-inside: avoid; border: 1px solid #e2e8f0; border-radius: 6px; padding: 15px; margin-bottom: 20px; background: #ffffff; }
            .sev-title { font-size: 13pt; font-weight: bold; margin-bottom: 10px; }
            .CRITICAL { border-left: 5px solid #991b1b; } .HIGH { border-left: 5px solid #ea580c; }
            .MEDIUM { border-left: 5px solid #eab308; } .LOW { border-left: 5px solid #3b82f6; }
            
            .issue-meta { font-size: 9pt; background: #f1f5f9; padding: 8px; border-radius: 4px; color: #475569; margin-bottom: 10px; display: inline-block; width: 100%; box-sizing: border-box; }
            .evidence-box { background: #1e293b; color: #f8fafc; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 8.5pt; margin-top: 10px; word-wrap: break-word; }
        </style>
    </head>
    <body>
        <div class="cover">
            <h1>Riskwise Security Report</h1>
            <h2>Automated Vulnerability Assessment</h2>
            
            <table class="meta-table">
                <tr><th>Task Name</th><td>{{ scan.task_name }}</td></tr>
                <tr><th>Scan ID</th><td>{{ scan.id }}</td></tr>
                <tr><th>Audit Depth</th><td>{{ scan.scan_level | upper }}</td></tr>
                <tr><th>Date of Report</th><td>{{ date }}</td></tr>
                <tr><th>Total Findings</th><td>{{ issues|length }} (Critical: {{ scan.critical_count }}, High: {{ scan.high_count }})</td></tr>
            </table>
        </div>
        
        <h2 class="section-header">Executive AI Insights</h2>
        <div class="ai-summary">{{ ai_html | safe }}</div>

        <h2 class="section-header">Vulnerability Details</h2>
        {% for issue in issues %}
        <div class="issue-card {{ issue.primary_severity }}">
            <div class="sev-title">[{{ issue.primary_severity }}] {{ issue.title }}</div>
            
            <div class="issue-meta">
                <b>CWE:</b> {{ issue.cwe or 'None' }} &nbsp;|&nbsp; <b>OWASP:</b> {{ issue.owasp or 'General' }} &nbsp;|&nbsp; <b>Status:</b> {{ issue.status | upper }}
            </div>
            
            <div style="font-size: 9.5pt; font-weight: bold;">Correlated Evidence:</div>
            {% for finding in issue.findings %}
            <div class="evidence-box">
                [{{ finding.scanner_type }}] {{ finding.description }}<br/>
                Location: {{ finding.evidence }}
            </div>
            {% endfor %}
        </div>
        {% endfor %}
    </body>
    </html>
    """
    
    reports_dir = os.path.join(settings.UPLOAD_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    # 1. Convert Markdown to Raw HTML
    raw_html = markdown.markdown(scan.executive_summary or "No AI Summary compiled.")
    
    # 2. Sanitize against LFI / Server-Side XSS
    safe_html = sanitize_ai_html(raw_html)
    
    template = Template(html_template)
    rendered_html = template.render(
        scan=scan, 
        issues=issues, 
        ai_html=safe_html, 
        date=scan.scanned_at.strftime("%Y-%m-%d %H:%M")
    )
    
    pdf_path = os.path.join(reports_dir, f"report_{scan.id}.pdf")
    
    try:
        from weasyprint import HTML
        HTML(string=rendered_html).write_pdf(pdf_path)
        return pdf_path
    except Exception as e:
        print(f"[PDF ERROR] Weasyprint binary failure: {e}")
        fallback_path = pdf_path.replace(".pdf", ".html")
        with open(fallback_path, "w", encoding="utf-8") as f:
            f.write(rendered_html)
        return fallback_path