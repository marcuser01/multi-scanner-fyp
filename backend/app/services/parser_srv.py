import re
import html
from typing import Optional, List

# ---------------------------------------------------------
# COMPLIANCE MAPPING: Extended CWE to OWASP 2021 Dictionary
# ---------------------------------------------------------
CWE_TO_OWASP_2021 = {
    # Injection
    "CWE-79": "A03:2021 - Injection (XSS)", 
    "CWE-89": "A03:2021 - Injection (SQLi)",
    "CWE-78": "A03:2021 - Injection (OS Command)", 
    "CWE-20": "A03:2021 - Injection (Improper Input Validation)",
    
    # Broken Access Control
    "CWE-352": "A01:2021 - Broken Access Control (CSRF)", 
    "CWE-22": "A01:2021 - Broken Access Control (Path Traversal)",
    "CWE-306": "A01:2021 - Broken Access Control (Missing Auth)",
    "CWE-668": "A01:2021 - Broken Access Control (Exposure of Resource)",
    "CWE-639": "A01:2021 - Broken Access Control (IDOR)",
    
    # Cryptographic Failures
    "CWE-319": "A02:2021 - Cryptographic Failures (Cleartext Transmission)",
    "CWE-327": "A02:2021 - Cryptographic Failures (Broken Crypto)",
    
    # Identification and Authentication Failures
    "CWE-287": "A07:2021 - Identification and Auth Failures",
    "CWE-798": "A07:2021 - Identification and Auth Failures (Hardcoded Secrets)",
    
    # Security Misconfiguration
    "CWE-489": "A05:2021 - Security Misconfiguration (Active Debug Code)",
    "CWE-117": "A09:2021 - Security Logging and Monitoring Failures",
    
    # Server-Side Request Forgery
    "CWE-918": "A10:2021 - Server-Side Request Forgery",
    
    # Software and Data Integrity Failures
    "CWE-502": "A08:2021 - Software and Data Integrity Failures (Deserialization)"
}

def clean_title(check_id: Optional[str], vulnerability_class: Optional[str]) -> str:
    """Safely extracts a human-readable title, prioritizing rule IDs over generic 'Other' tags."""
    if not check_id: 
        return "Unknown Vulnerability"
        
    if vulnerability_class and vulnerability_class.lower() not in ["n/a", "general", "audit", "other", ""]:
        return vulnerability_class
        
    # If the class is "Other", fallback to parsing the check_id cleanly
    parts = check_id.split('.')
    important_parts = parts[-2:] if len(parts) > 1 else parts
    raw = " ".join(important_parts).replace('-', ' ').replace('_', ' ')
    return raw.replace('avoid', '').replace('detected', '').strip().title()

def _get_latest_owasp(owasp_list: List[str]) -> str:
    """Safely extracts the most recent OWASP version from a list by parsing the Year."""
    def get_year(item: str) -> int:
        # Matches the year portion: A03:2021 -> extracts 2021
        match = re.search(r':(\d{4})', str(item))
        return int(match.group(1)) if match else 0
    
    # Filter only valid OWASP strings
    valid_owasp = [str(x) for x in owasp_list if re.search(r'A\d{1,2}:\d{4}', str(x))]
    
    if not valid_owasp:
        return str(owasp_list[0]) if owasp_list else "General / Uncategorized"
        
    # Return the one with the highest year (Prefers 2025/2021 over 2017)
    return max(valid_owasp, key=get_year)

def extract_owasp(metadata: dict, cwe_clean: Optional[str] = None, scanner_type: str = "SAST") -> str:
    """Intelligent OWASP categorization engine handling metadata, CWE mapping, and scanner fallbacks."""
    # 1. Try Semgrep native OWASP metadata first
    owasp_data = metadata.get("owasp")
    if owasp_data:
        if isinstance(owasp_data, list) and len(owasp_data) > 0:
            return _get_latest_owasp(owasp_data)
        elif isinstance(owasp_data, str):
            return owasp_data
            
    # 2. Fallback: Map from CWE explicitly (Fixes ZAP and Trivy OS vulns)
    if cwe_clean and cwe_clean in CWE_TO_OWASP_2021:
        return CWE_TO_OWASP_2021[cwe_clean]
        
    # 3. Ultimate Fallbacks by Scanner Context
    if scanner_type == "SCA":
        return "A06:2021 - Vulnerable and Outdated Components"
    
    return "General / Uncategorized"

# ---------------------------------------------------------
# SCANNER NORMALIZERS
# ---------------------------------------------------------

def normalize_semgrep_results(raw_json: dict, scan_id: str) -> list:
    normalized = []
    for item in raw_json.get("results", []):
        try:
            extra = item.get("extra", {})
            metadata = extra.get("metadata", {})

            # CWE Extraction
            cwe_raw = metadata.get("cwe", [])
            cwe_clean = None
            if isinstance(cwe_raw, list) and len(cwe_raw) > 0:
                cwe_match = re.search(r'CWE-\d+', str(cwe_raw[0]), re.IGNORECASE)
                cwe_clean = cwe_match.group(0).upper() if cwe_match else str(cwe_raw[0])

            # Class Extraction
            vuln_class_list = metadata.get("vulnerability_class", [])
            vuln_class = vuln_class_list[0] if isinstance(vuln_class_list, list) and len(vuln_class_list) > 0 else "General"

            # FIX: Strip the absolute backend upload path to make UI and PDF clean!
            raw_path = item.get("path", "Unknown File")
            clean_path = re.sub(r'^.*/uploads/[a-f0-9-]+/src/', '', raw_path)

            normalized.append({
                "scanner_type": "SAST",
                "title": clean_title(item.get("check_id"), vuln_class),
                "severity": extra.get("severity", "INFO").replace("ERROR", "HIGH").replace("WARNING", "MEDIUM"),
                "description": extra.get("message", "No description."),
                "cwe": cwe_clean,
                "owasp": extract_owasp(metadata, cwe_clean, "SAST"),
                "vulnerability_id": cwe_clean,
                "evidence": {
                    "file": clean_path, 
                    "line": item.get("start", {}).get("line", 0)
                }
            })
        except Exception as e:
            print(f"[Parser Warning] Skipped malformed Semgrep finding: {e}")
            
    return normalized


def normalize_trivy_results(raw_json: dict, scan_id: str) -> list:
    normalized = []
    # Loop covers both Vulnerabilities and Misconfigurations
    for result in raw_json.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) + result.get("Misconfigurations", []):
            try:
                cve_id = vuln.get("VulnerabilityID") or vuln.get("ID", "Unknown")
                cwe_list = vuln.get("CweIDs", [])
                cwe_clean = cwe_list[0] if isinstance(cwe_list, list) and len(cwe_list) > 0 else None

                normalized.append({
                    "scanner_type": "SCA",
                    "title": vuln.get("Title", f"Dependency/Config Issue: {vuln.get('PkgName', cve_id)}"),
                    "severity": vuln.get("Severity", "INFO").upper(),
                    "description": vuln.get("Description", "No description provided."),
                    "cwe": cwe_clean,
                    "owasp": extract_owasp({}, cwe_clean, "SCA"),
                    "vulnerability_id": cve_id,
                    "evidence": {
                        "package": vuln.get('PkgName', 'Unknown'),
                        "installed_version": vuln.get('InstalledVersion', 'Unknown'),
                        "fixed_version": vuln.get('FixedVersion', 'None')
                    }
                })
            except Exception as e:
                print(f"[Parser Warning] Skipped malformed Trivy finding: {e}")
                
    return normalized


def normalize_zap_results(raw_json: dict, scan_id: str) -> list:
    normalized = []
    risk_map = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}

    for site in raw_json.get("site", []):
        for alert in site.get("alerts", []):
            try:
                instances = alert.get("instances", [])
                target_url = instances[0].get("uri", "Unknown URL") if instances else "Unknown URL"
                method = instances[0].get("method", "GET") if instances else "GET"

                raw_desc = alert.get("desc", "No description.")
                clean_desc = html.unescape(re.sub(r'<[^>]+>', '', str(raw_desc)))

                cwe_raw = alert.get("cweid")
                cwe_clean = f"CWE-{cwe_raw}" if cwe_raw and str(cwe_raw) != "-1" else None

                normalized.append({
                    "scanner_type": "DAST",
                    "title": alert.get("alert", "Unknown DAST Alert"),
                    "severity": risk_map.get(str(alert.get("riskcode", "0")), "INFO").upper(),
                    "description": clean_desc,
                    "cwe": cwe_clean,
                    "owasp": extract_owasp({}, cwe_clean, "DAST"),
                    "vulnerability_id": cwe_clean,
                    "evidence": {
                        "url": target_url,
                        "method": method
                    }
                })
            except Exception as e:
                print(f"[Parser Warning] Skipped malformed ZAP finding: {e}")
                
    return normalized