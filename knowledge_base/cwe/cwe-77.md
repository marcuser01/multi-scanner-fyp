# CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')

## Description

The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component. While OS shell injections are the most common, this vulnerability applies to any custom command language used by a product or protocol.

## Why This Matters (Security Impact)

Command injection is one of the most dangerous vulnerabilities because it allows an attacker to interact directly with the underlying system or environment.

* **Execute Unauthorized Code:** By injecting delimiters (like `;`, `&`, `|`, or newline characters), an attacker can terminate the intended command and start a completely new, malicious one.
* **Privilege Escalation:** Malicious commands are executed with the privileges of the vulnerable application. If the application runs as `root` or `SYSTEM`, the attacker effectively gains full control of the machine.
* **Full System Compromise:** An attacker can read sensitive files, delete data, or install persistent malware/backdoors.

## Common Consequences

* **Execute Unauthorized Code or Commands:** Total loss of Integrity, Confidentiality, and Availability as the attacker runs arbitrary system-level instructions.

## Likelihood of Exploit

**High**
If an application passes raw user input to a system shell or a command-line interpreter, exploitation is often trivial and highly reliable.

## How This Is Typically Detected

* **Automated Static Analysis (SAST):** Highly effective. Tools trace the flow of data from untrusted "sources" (API parameters, headers) to "sinks" that execute commands (like `system()`, `exec()`, or `popen()`). (Effectiveness: High).
* **Fuzzing:** Sending common command injection payloads (e.g., `; ls`, `| whoami`) to input fields and monitoring for changes in the response or system behavior.
* **Dynamic Analysis:** Monitoring system calls during execution to see if unexpected sub-processes are being spawned.

## Potential Mitigations

### Architecture and Design

* **Use Built-in Library Calls:** Instead of calling an external process to perform a task (e.g., using `os.system('rm file')`), use the programming language's native API (e.g., `os.remove('file')`). This avoids the shell entirely.
* **Static Commands:** Ensure that the commands being executed are fixed strings. If arguments are needed, pass them as a list to an API that does not invoke a shell.

### Implementation

* **Strategy: "Accept Known Good":** Use an **allowlist** to validate input. Only allow characters that are strictly necessary (e.g., alphanumeric only). Reject any input containing command delimiters or special characters.
* **Input Validation:** Don't just look for "bad" characters (denylist); they are easy to miss. Validate the length, type, and syntax of the input against strict business rules.

### System Configuration & Operation

* **Principle of Least Privilege:** Run the application with the minimum necessary permissions to reduce the impact if an injection occurs.
* **Runtime Policy Enforcement:** Use an allowlist of sanctioned commands at the OS level to prevent the execution of unexpected binaries.

## Simplified Example

```python
# VULNERABLE: Input is concatenated directly into a shell command
import os
def check_network(ip_address):
    # An attacker could provide "8.8.8.8; rm -rf /"
    os.system("ping -c 1 " + ip_address)

# SECURE: Using a library call with a list of arguments (no shell)
import subprocess
def check_network(ip_address):
    # subprocess.run with a list handles arguments safely without a shell
    subprocess.run(["ping", "-c", "1", ip_address], shell=False)

```

## References

* [REF-44] 24 Deadly Sins of Software Security: Command Injection
* [REF-6] Seven Pernicious Kingdoms: Taxonomy of Software Security Errors
* [REF-140] Exploiting Software: How to Break Code
* [REF-1287] MITRE: Problematic Mappings in Top 25
