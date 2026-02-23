import os
import sqlite3
import hashlib
import base64
import requests
import pickle
import jwt  # Added for JWT testing
import subprocess
from flask import Flask, request, make_response, send_from_directory

app = Flask(__name__)

# CWE-798: Hardcoded Credentials (Context: AWS/Internal Access)
AWS_ACCESS_KEY = "AKIAEXAMPLE123456789"
ADMIN_TOKEN = "dGhpcy1pcy1hLXNlY3JldC1hZG1pbi10b2tlbg=="

@app.route("/api/v1/user/config")
def get_config():
    # CWE-22: Path Traversal (Insecure file access)
    # Context: Could allow reading /etc/passwd or AWS credentials files
    filename = request.args.get("file")
    return send_from_directory("/etc/app/config", filename)

@app.route("/api/v1/debug/shell")
def internal_shell():
    # CWE-78: OS Command Injection via shell=True
    # Context: Architect-only tool that allows arbitrary execution
    cmd = request.args.get("cmd")
    output = subprocess.check_output(cmd, shell=True)
    return output

@app.route("/api/v1/auth/legacy")
def legacy_auth():
    # CWE-287: Improper Authentication
    # CWE-327: Use of Broken Crypto (Base64 is NOT encryption)
    auth_header = request.headers.get("Authorization")
    user_data = base64.b64decode(auth_header).decode()
    if "admin=true" in user_data:
        return "Access Granted to Admin Console"
    return "Access Denied"

@app.route("/api/v1/transfer", methods=["POST"])
def transfer_funds():
    # CWE-352: Cross-Site Request Forgery (CSRF)
    # Context: No CSRF protection on a sensitive state-changing operation
    amount = request.form.get("amount")
    to_account = request.form.get("account")
    return f"Transferred {amount} to {to_account}"

@app.route("/api/v1/jwt/decode")
def decode_token():
    # CWE-345: Insufficient Verification of Data Integrity
    # Context: Using jwt.decode without verifying the signature (None algorithm attack)
    token = request.args.get("token")
    decoded = jwt.decode(token, options={"verify_signature": False})
    return decoded

@app.route("/api/v1/logs")
def view_logs():
    # CWE-117: Improper Output Neutralization for Logs (Log Injection)
    # Context: Attacker can inject newlines to forge log entries
    user_input = request.args.get("service_name")
    app.logger.info(f"User requested logs for service: {user_input}")
    return "Log entry created"

@app.route("/api/v1/profile")
def profile():
    # CWE-639: IDOR (Insecure Direct Object Reference)
    # Context: User can change 'id' to see other profiles without auth check
    user_id = request.args.get("id")
    conn = sqlite3.connect('database.db')
    cursor = conn.execute(f"SELECT username, email FROM users WHERE id = {user_id}")
    return str(cursor.fetchone())

@app.route("/api/v1/ping")
def network_ping():
    # CWE-918: SSRF (Internal Network Scanning)
    # Context: Used by architects to check health of internal VPC services
    target = request.args.get("host")
    response = requests.get(f"http://{target}/health", timeout=2)
    return response.text

if __name__ == "__main__":
    # CWE-209: Information Exposure (Stack traces in prod-like environment)
    app.run(host="0.0.0.0", port=5000, debug=True)
