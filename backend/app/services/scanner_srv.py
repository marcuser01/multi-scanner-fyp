# backend/app/services/scanner_srv.py
import subprocess
import json
import os
import shutil
from app.core.config import settings

class SemgrepScanner:
    @staticmethod
    def execute(scan_id: str, target_dir: str, configs: list):
        semgrep_bin = shutil.which("semgrep")
        if not semgrep_bin: 
            return None

        output_path = os.path.abspath(os.path.join(settings.UPLOAD_DIR, f"{scan_id}_semgrep.json"))
        command = [
            semgrep_bin, "scan", "--json", f"--json-output={output_path}",
            "--verbose",  # Live verbose tracking
            "--metrics=off", "--exclude=node_modules", "--exclude=.venv", "--no-git-ignore"
        ]
        for c in configs: 
            command.append(f"--config={c}")
        command.append(os.path.abspath(target_dir))
        
        env = os.environ.copy()
        env["OTEL_SDK_DISABLED"] = "true"

        print(f"\n[SEMGREP] 🚀 Starting Semgrep Scan for ID {scan_id}...")
        try:
            # Streams standard output directly to server logs in real-time
            subprocess.run(command, check=False, env=env, timeout=300)
            if os.path.exists(output_path):
                with open(output_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"  [Semgrep EXCEPTION]: {str(e)}")
        return None

class TrivyScanner:
    @staticmethod
    def execute(scan_id: str, target_dir: str):
        trivy_bin = shutil.which("trivy")
        if not trivy_bin: return None

        output_path = os.path.abspath(os.path.join(settings.UPLOAD_DIR, f"{scan_id}_trivy.json"))
        
        command = [
            trivy_bin, "fs", "--scanners", "vuln,secret,misconfig", 
            # "--debug", # Tip: You can comment this out in production to save terminal spam
            "--format", "json", "--output", output_path,
            "--skip-dirs", "node_modules", 
            "--skip-dirs", ".venv", # FIX: Skip virtual environments to prevent 10-minute timeouts
            os.path.abspath(target_dir)
        ]

        print(f"\n[TRIVY] 🚀 Starting Trivy Scan for ID {scan_id}...")
        try:
            subprocess.run(command, check=False, timeout=600)
            if os.path.exists(output_path):
                with open(output_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"  [Trivy EXCEPTION]: {str(e)}")
        return None

class ZapScanner:
    @staticmethod
    def _is_docker_running():
        """Checks if backend can communicate with the Secure Docker Proxy"""
        try:
            result = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False
        
    @staticmethod
    def _get_current_docker_network():
        """
        Dynamically retrieves the network name. 
        Defaults to 'multi-scanner-fyp_default' if not set in environment.
        """
        return os.getenv("DOCKER_NETWORK_NAME", "multi-scanner-fyp_default")

    @staticmethod
    def _get_dynamic_resources():
        """
        Dynamically calculates host memory and returns appropriate JVM heap allocation
        and active thread throttling values.
        """
        # Ensure 'os' is imported (already at top of file, but kept here for absolute safety)
        import os
        total_gb = 4.0 # Default fallback
        
        # 1. Try cross-platform psutil library first
        try:
            import psutil
            total_gb = psutil.virtual_memory().total / (1024 ** 3)
        except ImportError:
            # 2. Fallback to Unix/Linux sysconf if psutil is not installed
            try:
                page_size = os.sysconf("SC_PAGE_SIZE")
                phys_pages = os.sysconf("SC_PHYS_PAGES")
                total_gb = (page_size * phys_pages) / (1024 ** 3)
            except Exception:
                pass # Use default 4.0 GB
        
        # Dynamic Resource Scaling Table (Outputs raw size strings)
        if total_gb <= 4.0:
            jvm_heap = "1024m" # 1GB Heap
            threads = "2"
        elif total_gb <= 8.0:
            jvm_heap = "1536m" # 1.5GB Heap (Perfect balance for 6GB-8GB hosts)
            threads = "2"      # Restrict threads to prevent OOM
        elif total_gb <= 16.0:
            jvm_heap = "3072m" # 3GB Heap
            threads = "5"
        else:
            jvm_heap = "6144m" # 6GB Heap
            threads = "10"
            
        return jvm_heap, threads


    @staticmethod
    def execute(scan_id: str, target_url: str, dast_mode: str = "baseline"):
        docker_bin = shutil.which("docker")
        if not docker_bin: 
            print("[ZAP ERROR]: Docker binary not found on host!")
            return None

        if not ZapScanner._is_docker_running():
            raise Exception("Docker Proxy is offline or API access is blocked.")

        output_filename = "report.json"
        
        host_uploads_dir = os.getenv("HOST_UPLOADS_DIR")
        if not host_uploads_dir:
            host_uploads_dir = os.path.abspath(settings.UPLOAD_DIR)

        # Narrow-Scope Mounting (Least Privilege)
        host_scan_dir = os.path.join(host_uploads_dir, scan_id)
        container_scan_dir = os.path.join(os.path.abspath(settings.UPLOAD_DIR), scan_id)
        output_path = os.path.join(container_scan_dir, output_filename)
        
        script_name = "zap-full-scan.py" if dast_mode == "full" else "zap-baseline.py"
        scan_timeout = 7200 if dast_mode == "full" else 900
        container_name = f"zap_scan_{scan_id}"
        target_network = ZapScanner._get_current_docker_network()
        
        # Calculate optimal system parameters for this specific host machine
        jvm_heap, threads = ZapScanner._get_dynamic_resources()

        # Build execution parameters
        command = [
            docker_bin, "run", "--rm", 
            "--name", container_name,
            "--network", target_network,
            "-e", f"ZAP_JVM_ARGS=-Xmx{jvm_heap}", 
            "-v", f"{host_scan_dir}:/zap/wrk/:rw,Z", 
            "ghcr.io/zaproxy/zaproxy:stable", 
            script_name, "-t", target_url, "-d", "-J", output_filename
        ]

        # Apply thread throttling to ZAP configurations during Active Scanning
        if dast_mode == "full":
            command.extend(["-z", f"-config scanner.threadPerHost={threads}"])

        print(f"\n[ZAP] 🚀 Starting ZAP {script_name} for ID {scan_id}... (Timeout: {scan_timeout}s)")
        print(f"  [ZAP CONFIG] Host Memory Evaluated: {jvm_heap} Max Heap | Active Threads: {threads}")
        
        try:
            subprocess.run(command, check=False, timeout=scan_timeout)
            
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                with open(output_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                print("[ZAP ERROR]: ZAP finished but report is missing or empty.")
                return None
                
        except subprocess.TimeoutExpired:
            print(f"  [ZAP TIMEOUT]: Scan exceeded {scan_timeout} seconds! Force killing container {container_name}...")
            subprocess.run([docker_bin, "rm", "-f", container_name], capture_output=True, check=False)
            return None
            
        except Exception as e:
            print(f"  [ZAP EXCEPTION]: {str(e)}")
            # Ensure cleanup happens on unexpected crashes too
            subprocess.run([docker_bin, "rm", "-f", container_name], capture_output=True, check=False)
            return None