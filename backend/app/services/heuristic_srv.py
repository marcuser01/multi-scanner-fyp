from typing import List
from app.models.database import CorrelatedIssue, NormalizedFinding

def run_heuristic_deduplication(scan_id: str, raw_findings: List[dict], db_session) -> None:
    clusters = {}

    for f in raw_findings:
        cwe = f.get("cwe") or "UNKNOWN_CWE"
        evidence = f.get("evidence", {})

        loc_key = "global"
        if "file" in evidence:
            loc_key = evidence["file"].split("/")[-1]
        elif "url" in evidence:
            loc_key = evidence["url"].split("?")[0].strip("/")
        elif "package" in evidence:
            loc_key = evidence["package"]

        cluster_key = f"{cwe}_{loc_key}"
        if cluster_key not in clusters: clusters[cluster_key] = []
        clusters[cluster_key].append(f)

    sev_ranking = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    for key, findings in clusters.items():
        max_sev = "INFO"
        best_owasp = None

        for f in findings:
            if sev_ranking.get(f.get("severity", "INFO"), 0) > sev_ranking.get(max_sev, 0):
                max_sev = f.get("severity", "INFO")
            # Grab OWASP tag if present in any of the correlated findings
            if not best_owasp and f.get("owasp"):
                best_owasp = f.get("owasp")

        # Create Parent Correlated Issue
        issue = CorrelatedIssue(
            scan_id=scan_id,
            title=findings[0]["title"],
            primary_severity=max_sev,
            cwe=findings[0].get("cwe"),
            owasp=best_owasp  # Saved to database
        )
        db_session.add(issue)
        db_session.flush()

        # Save exact tools evidence
        for f in findings:
            nf = NormalizedFinding(
                issue_id=issue.id,
                scanner_type=f["scanner_type"],
                vulnerability_id=f.get("vulnerability_id"),
                description=f.get("description"),
                evidence=f.get("evidence")
            )
            db_session.add(nf)

    db_session.commit()
