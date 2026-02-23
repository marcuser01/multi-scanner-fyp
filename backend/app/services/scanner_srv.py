# backend/app/services/scanner_srv.py
import subprocess
import json
import os
from app.core.config import settings

class SemgrepScanner:
    # Industry Standard Configs from Semgrep Registry
    # Changed 'auto' to 'p/default' to avoid the metrics-requirement error
    PROFILES = {
        "auto": "p/default",
        "owasp": "p/owasp-top-ten",
        "audit": "p/security-audit",
        "python": "p/python",
        "secrets": "p/secrets"
    }

    @staticmethod
    def execute(scan_id: str, target_dir: str, profile_key: str):
        # We can pass multiple configs to get that '16 findings' depth
        config = SemgrepScanner.PROFILES.get(profile_key, "p/python")
        
        output_path = os.path.abspath(os.path.join(settings.UPLOAD_DIR, f"{scan_id}_results.json"))
        abs_target = os.path.abspath(target_dir)

        command = [
            "semgrep", "scan",
            "--json",
            f"--config={config}",
            # If the user chose 'auto' or 'audit', let's double down on coverage
            f"--config=p/security-audit", 
            f"--json-output={output_path}",
            "--metrics=off",
            "--no-git-ignore", # CRITICAL: Scan files even if not in a git repo
            abs_target
        ]

        print(f"  [CLI] Running command: {' '.join(command)}")

        env = os.environ.copy()
        env["OTEL_SDK_DISABLED"] = "true"
        env["PYTHONIOENCODING"] = "utf-8" 

        try:
            # Semgrep returns 0 for success (no findings) or 1 for success (findings)
            # Anything else is a fatal error.
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                check=False, 
                env=env, 
                timeout=120 # Increased timeout for larger scans
            )
            
            if result.returncode not in [0, 1]:
                print(f"  [CLI] Semgrep Fatal Error Code: {result.returncode}")
                print(f"  [CLI] Stderr: {result.stderr}")

            if os.path.exists(output_path):
                with open(output_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                print(f"  [CLI] Error: Output file {output_path} was not created.")
            return None
        except subprocess.TimeoutExpired:
            print("  [CLI] Error: Semgrep timed out after 120s.")
            return None
        except Exception as e:
            print(f"  [CLI] Execution Exception: {str(e)}")
            return None