# 🛡️ Riskwise Security: AI-Assisted Multi-Scanner Vulnerability Platform

**Riskwise Security** is a locally-hosted, enterprise-grade Security Posture Management Platform designed for Small and Medium Enterprises (SMEs). It intelligently aggregates Static (SAST), Composition (SCA), and Dynamic (DAST) analysis into a unified dashboard, utilizing a **Retrieval-Augmented Generation (RAG) AI Engine** to contextualize vulnerabilities, map compliance frameworks, and provide actionable remediation guidance.

---

## ✨ Unique Selling Points (USPs)

1. **Heuristic Deduplication Engine:** Automatically correlates overlapping findings from multiple independent scanners (e.g., SAST and DAST both finding SQLi on the same endpoint) into a single, trackable issue.
2. **Two-Tier AI Triage (RAG):** Employs isolated AI workflows to provide both **Micro-Triage** (line-by-line code remediation) and **Macro-Triage** (executive-level CISO summaries) mapped securely against an internal OWASP/CWE vector database.
3. **Impenetrable "Security-First" Deployment:** Engineered to withstand internal penetration tests. Includes SSRF DNS-pinning, Zip-Slip protections, HttpOnly Secure sessions, and a strictly firewalled Docker-out-of-Docker (DooD) proxy.

---

## 🛠️ Technology Stack

| Layer | Technologies Used | Purpose |
| :--- | :--- | :--- |
| **Frontend** | React (Vite), TailwindCSS, Recharts | Fast, responsive Single Page Application (SPA). |
| **Backend** | Python 3.13, FastAPI, SQLAlchemy | Asynchronous API orchestration and business logic. |
| **Database** | SQLite (WAL Mode), ChromaDB | Concurrent relational data and semantic vector storage. |
| **Scanners** | Semgrep, Trivy, OWASP ZAP | Best-in-class open-source vulnerability analysis engines. |
| **Security/Infra** | Nginx, Docker Compose, Fernet AES-256 | TLS/HTTPS proxying, container isolation, and secret vaulting. |

---

## 🚀 Core Features & Implementation

### 1. Multi-Scanner Orchestration
Riskwise dynamically controls three distinct security engines without blocking the main event loop:
*   **SAST (Semgrep):** Analyzes raw source code for structural and logical flaws.
*   **SCA (Trivy):** Scans lockfiles (`package-lock.json`, etc.) and misconfigurations.
*   **DAST (OWASP ZAP):** Executes passive or active runtime exploits against live URLs.
*   *Implementation Note:* ZAP's Java Virtual Machine (JVM) heap memory and concurrent attack threads are **dynamically scaled at runtime** via `psutil` / `os.sysconf` to prevent Out-Of-Memory (OOM) host crashes.

### 2. Vulnerability Normalization & Workflow Management
All scanner JSON outputs are parsed and mapped to the **OWASP Top 10 (2021)** framework and standard **CWE** identifiers. The platform includes a full vulnerability management workflow allowing teams to assign issues, mark them as `Remediated`, and track resolution.

### 3. Automated PDF Report Generation
Riskwise automatically compiles scan metrics, correlated evidence traces, and the AI Executive Summary into a highly stylized, compliance-ready PDF.
*   *Implementation Note:* The AI-generated Markdown is sanitized via **Bleach** to prevent Server-Side XSS/LFI, rendered into a Jinja2 template, and exported via WeasyPrint.

---

## 🔒 Enterprise Security Posture

This application is defensively hardened against application and infrastructure-level attacks:

*   **Sandboxed Docker Proxy (Defeating DooD Escapes):** The backend web API **does not** have direct access to `/var/run/docker.sock`. It communicates through a strict `tecnativa/docker-socket-proxy` firewall, preventing compromised APIs from launching `--privileged` containers or mapping the host root filesystem.
*   **Least Privilege & SELinux:** The backend runs as a non-root system user (`riskwise`, UID 1000). DAST volumes use **Narrow-Scope Mounting** with private SELinux contexts (`:Z`), ensuring scanners cannot access cross-tenant data.
*   **Cryptographic Vaulting:** AI API Keys (e.g., OpenRouter, OpenAI) are never stored in plaintext. They are encrypted at-rest in the database using **AES-256 (Fernet)**.
*   **Session & Authentication Hardening:** 
    *   Passwords hashed securely via `bcrypt`.
    *   Stateless JWTs transmitted exclusively via `HttpOnly`, `Secure`, and `SameSite=Strict` cookies.
    *   Global CSRF protection enforced via `X-Requested-With` header validation.
*   **Network Security:** Nginx enforces **HTTPS/TLS**, `Strict-Transport-Security (HSTS)`, and tight Content Security Policies (CSP).
*   **Input Sanitization:** 
    *   **SSRF Protection:** DAST URLs undergo dynamic DNS-resolution to actively block RFC 1918 internal/private IP scanning.
    *   **Zip-Bomb/Slip:** Uploaded archives enforce a strict 500MB uncompressed ceiling and absolute path-traversal validation prior to extraction.

---

## 🧑‍💻 User Workflow (How to Use)

1. **First-Run Bootstrap:** Upon fresh installation, the first user to navigate to the platform is greeted by the Setup Screen and automatically granted `ADMIN` privileges.
2. **Vault Initialization:** The Admin navigates to the **Settings** tab and securely vaults their LLM API key.
3. **Launch Assessment:** Click **+ New Scan**. Provide a Task Name, select the Audit Depth, upload a `.zip` of your source code, and provide the live target URL.
4. **AI Triage:** Once the scanners complete, Riskwise aggregates the findings. Click **Inspect** on any issue to generate a tailored, contextual AI remediation plan grounded in OWASP best practices.
5. **Report & Remediate:** Download the final Executive PDF Report to sign-off on the security audit.

---

## ⚙️ Installation & Setup

### Prerequisites
*   **Linux / WSL2** (Recommended for file permission mapping)
*   **Docker Engine** (v20.0+)
*   **Docker Compose** (v2.0+)

### 1. Build and Launch
Clone the repository and launch the fully containerized environment. The internal `entrypoint.sh` script will automatically initialize the database and seed the Vector Knowledge Base.
```bash
git clone https://github.com/yourusername/multi-scanner-fyp.git
cd multi-scanner-fyp
docker compose up --build -d
```

### 2. Access the Platform
Navigate to the secure frontend proxy:
```text
https://localhost:5173
```
*(Note: Because the environment generates a self-signed TLS certificate locally during the build phase, your browser will display a "Connection Not Private" warning. Click **Advanced -> Proceed** to access the application securely).*

---

## 💻 Typical Maintenance Commands

**Watch live pipeline logs (Monitor active scanners):**
```bash
docker logs -f riskwise-backend
```

**View Nginx / Frontend Access Logs:**
```bash
docker logs -f riskwise-frontend
```

**Hard Reset (Nuclear Wipe):**
Use this command to completely purge all databases, encrypted keys, scan artifacts, and user accounts to return the system to a factory state.
```bash
docker compose down -v
sudo rm -rf backend/data/* backend/uploads/* backend/.fernet.key
```

---

## ❓ FAQ & Troubleshooting

**Q: OWASP ZAP (DAST) immediately fails and says "Docker Daemon is offline".**
*A: This usually means your host OS (especially Fedora/RHEL) is blocking the Docker Socket Proxy via SELinux. Ensure the `docker-compose.yml` proxy volume mount includes the `:ro,z` flag, and the proxy is running in `privileged: true` mode.*

**Q: The AI Executive Summary says "API Key not configured".**
*A: You must log in as an `ADMIN`, navigate to `Settings`, and save your OpenRouter/OpenAI API key into the encrypted vault before the RAG engine can function.*

**Q: Trivy (SCA) takes a very long time to complete.**
*A: If your uploaded `.zip` archive contains heavy dependency folders (like `node_modules` or `.venv`), Trivy must recursively unpack and evaluate thousands of binaries. The platform is configured to skip these folders automatically, but ensure you are uploading standard source code files and lockfiles (`package-lock.json`, `poetry.lock`) for optimal speed.*

**Q: Can a Developer run a full DAST attack?**
*A: No. By design, users with the `DEVELOPER` role are strictly restricted to passive/baseline DAST scanning to prevent accidental Denial of Service (DoS) against live staging environments. Only `ADMIN` and `ANALYST` roles can trigger intrusive payload injection.*
