# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

## Description

The product constructs an OS command using externally-influenced input but fails to neutralize special elements (command separators, pipes, redirects) that can modify the command. This allows attackers to execute arbitrary operating system commands with the privileges of the application.

### Subtypes

1. **Argument Injection:** The application intends to run a fixed program (e.g., `nslookup`) but uses untrusted input as an argument without removing separators like `;`, `&`, or `|`.
2. **Full Command Injection:** The application accepts an entire string from the user and passes it directly to a command shell (e.g., `exec([USER_INPUT])`).

## Why This Matters (Security Impact)

OS Command Injection is one of the most dangerous vulnerabilities because it provides a direct bridge from the application to the underlying host.

* **Arbitrary Code Execution:** Attackers can run any command the system user allows (e.g., `whoami`, `ls`, `cat /etc/passwd`).
* **System Takeover:** If the application runs with root or administrative privileges, the attacker gains full control of the server.
* **Lateral Movement:** The compromised server can be used as a pivot point to attack other internal systems.

## Common Consequences

* **Execute Unauthorized Commands:** Full access to the OS command line.
* **Data Disclosure/Modification:** Reading or deleting files and application data.
* **Denial of Service:** Executing commands that crash the system or consume all CPU/Memory.
* **Hide Activities:** Malicious actions appear to originate from the legitimate application.

## Likelihood of Exploit

**High**
Command injection is easy to detect and exploit, often requiring only basic knowledge of shell syntax.

## How This Is Typically Detected

* **Automated Static Analysis (SAST):** Tools like **Semgrep** find "sinks" that invoke the shell (e.g., `system()`, `os.system()`, `exec()`) and trace them back to untrusted "sources." (Effectiveness: High).
* **Automated Dynamic Analysis (DAST):** Fuzzing input fields with characters like `; sleep 10` to observe time delays or unintended command execution. (Effectiveness: Moderate).
* **Manual Review:** Identifying logic where the application interacts with the OS for tasks like image processing, network diagnostics, or file compression. (Effectiveness: High).

## Potential Mitigations

* **Avoid External Calls (Primary):** Use built-in library functions instead of calling external OS processes (e.g., use a native SMTP library instead of calling the `mail` command).
* **Parameterization (Strongest Defense):** Use structured APIs that do not invoke a shell. Pass arguments as a list rather than a single string.
* **C:** Use `execl()` or `execve()` instead of `system()`.
* **Python:** Use `subprocess.run(["ls", directory])` with `shell=False`.


* **Input Validation (Allowlist):** Strictly validate input against an alphanumeric allowlist. Reject any input containing characters like `& | ; $ > < ' " \ !`.
* **Principle of Least Privilege:** Run the application under a low-privilege user account and use a **Sandbox/Jail** (e.g., AppArmor, SELinux, or Docker) to limit the commands it can execute.
* **Environment Hardening:** Use runtime taint analysis (e.g., Perl's `-T` switch) to prevent tainted data from reaching command execution sinks.

## Simplified Example

```python
# VULNERABLE: shell=True invokes a shell, allowing ";" to inject new commands
import subprocess
address = request.args.get("address")
subprocess.run("nslookup " + address, shell=True) # Input: "8.8.8.8; cat /etc/passwd"

# SECURE: shell=False (default) treats input as a single literal argument
import subprocess
address = request.args.get("address")
subprocess.run(["nslookup", address], shell=False) 

```

## References

* [REF-867] OWASP Command Injection Defense Cheat Sheet
* [REF-1449] CISA Alert: Eliminating OS Command Injection
* [REF-44] 24 Deadly Sins of Software Security: Command Injection
* [REF-1481] D3FEND: Application Layer Firewall
