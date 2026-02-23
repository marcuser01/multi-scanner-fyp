# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## Description

The product uses external input to construct a pathname intended to identify a file or directory beneath a restricted parent directory, but fails to neutralize special elements (e.g., `..`, `/`, `\`). This allows attackers to escape the restricted location and access files or directories elsewhere on the system.

### Variants

* **Relative Path Traversal:** Using `../` sequences to move up the directory hierarchy.
* **Absolute Path Traversal:** Providing full paths (e.g., `/etc/passwd` or `C:\Windows\`) to bypass the intended directory entirely.
* **Null Byte Injection:** Using `%00` to truncate file extensions added by the application.

## Why This Matters (Security Impact)

Path traversal can lead to total system compromise by allowing attackers to:

* **Read Sensitive Files:** Access configuration files, credentials, or source code.
* **Execute Unauthorized Code:** Overwrite critical system libraries or web scripts.
* **Modify System State:** Append new users to password files or delete essential data.

## Common Consequences

* **Confidentiality Breach:** Exposure of sensitive data from unexpected files.
* **Integrity Violation:** Overwriting or creating critical files to bypass security mechanisms.
* **Availability Loss:** Corrupting or deleting files necessary for the product to function.

## Likelihood of Exploit

**High**
Path traversal is a well-known vulnerability that is easy to test for and automate, often leading to immediate high-impact data exposure.

## How This Is Typically Detected

* **Automated Static Analysis (SAST):** Tools like **Semgrep** identify where untrusted input is used in file system APIs (e.g., `open()`, `File()`) without prior canonicalization. (Effectiveness: High).
* **Dynamic Analysis (DAST):** Fuzzing parameters with payloads like `../../etc/passwd` and monitoring for unexpected file content in responses. (Effectiveness: High).
* **Manual Review:** Assessing if the business logic correctly maps user IDs to specific files rather than allowing direct name input. (Effectiveness: High).

## Potential Mitigations

* **Input Validation (Allowlist):** Use a strict allowlist of alphanumeric characters for filenames. Reject any input containing directory separators (`/`, `\`) or more than one ".".
* **Canonicalization:** Before validation, decode and resolve the path to its simplest form using built-in functions:
* C: `realpath()`
* Java: `getCanonicalPath()`
* Python: `os.path.abspath()`
* PHP: `realpath()`


* **Enforcement by Conversion:** Map user input to internal IDs (e.g., `file_id=1`) rather than accepting filenames directly.
* **Sandboxing/Jailing:** Use OS-level features like `chroot`, **AppArmor**, or **SELinux** to restrict the application's file system view.
* **Principle of Least Privilege:** Run the application under an account with the minimum permissions required to access only the necessary directories.
* **Environment Hardening:** Store sensitive utility and include files outside of the web document root.

## Simplified Example

```python
# VULNERABLE: Direct concatenation allows "../"
filename = request.args.get("file")
with open("/var/www/uploads/" + filename, "rb") as f:
    return f.read()

# SECURE: Use os.path.basename to strip path info and validate
import os
filename = os.path.basename(request.args.get("file"))
safe_path = os.path.join("/var/www/uploads/", filename)
with open(safe_path, "rb") as f:
    return f.read()

```

## References

* [REF-185] OWASP: Testing for Path Traversal
* [REF-1448] CISA Alert: Eliminating Directory Traversal Vulnerabilities
* [REF-186] SANS Top 25: Path Traversal
* [REF-1482] D3FEND: Trusted Library (D3-TL)