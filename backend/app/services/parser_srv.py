import re

def clean_title(check_id, vulnerability_class):
    # Priority 1: Use the official Vulnerability Class if it's specific
    if vulnerability_class and vulnerability_class not in ["N/A", "General", "audit"]:
        return vulnerability_class

    # Priority 2: Clean the check_id
    # e.g., "python.lang.security.deserialization.pickle.avoid-pickle"
    parts = check_id.split('.')
    # Take the last two meaningful parts
    important_parts = parts[-2:] if len(parts) > 1 else parts
    
    # Join, remove hyphens/underscores, and clean up
    raw = " ".join(important_parts).replace('-', ' ').replace('_', ' ')
    
    # Remove redundant words often found in semgrep IDs
    raw = raw.replace('avoid', '').replace('detected', '').strip()
    
    return raw.title()

def normalize_semgrep_results(raw_json, scan_id):
    normalized_findings = []
    summary = {
        "rules_run": len(raw_json.get("results", [])),
        "duration": raw_json.get("time", {}).get("profiling_times", {}).get("total_time", 0)
    }

    # Define the severity mapping
    sev_map = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW"
    }

    for item in raw_json.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        
        # Clean CWE ID
        raw_cwe_list = metadata.get("cwe", [])
        cwe_id = "unknown"
        if raw_cwe_list:
            match = re.search(r'(CWE-\d+)', raw_cwe_list[0], re.IGNORECASE)
            if match:
                cwe_id = match.group(1).lower()

        # Extract OWASP info
        # owasp_full example: "A03:2021 - Injection"
        owasp_full = metadata.get("owasp", ["N/A"])[0]
        # owasp_id example: "A03"
        owasp_id = owasp_full.split(':')[0] if ':' in owasp_full else owasp_full
        
        v_class = metadata.get("vulnerability_class", ["General"])[0]

        finding = {
            "scan_id": scan_id,
            "title": clean_title(item.get("check_id"), v_class),
            # Map Semgrep severity to your custom labels, defaulting to "INFO" if unknown
            "severity": sev_map.get(extra.get("severity"), "INFO"),
            "file_path": item.get("path"),
            "line_number": item.get("start", {}).get("line"),
            "description": extra.get("message"),
            "cwe": cwe_id,
            "owasp": owasp_id,
            "owasp_full": owasp_full, # Stores the full name as per JSON output
            "vulnerability_class": v_class,
            "raw_json": extra 
        }
        normalized_findings.append(finding)
        
    return normalized_findings, summary