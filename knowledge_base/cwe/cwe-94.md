# CWE-94: Improper Control of Generation of Code ('Code Injection')

## Description

The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment. This allows for the injection of **control plane data** into the **user-controlled data plane**, meaning the execution of the process may be altered simply by sending code through legitimate data channels.

## Why This Matters (Security Impact)

Unlike other flaws that require additional memory vulnerabilities to gain execution, code injection only requires the data to be **parsed**.

* **Arbitrary Code Execution:** Attackers can craft code syntax to alter the intended control flow, executing commands with the application's privileges.
* **Bypass Protection Mechanism:** If the injectable code controls authentication logic, it can lead to remote vulnerabilities.
* **Loss of Data Integrity:** Since the injected control-plane data is incidental to data recall or writing, integrity is lost in nearly all cases.
* **Hide Activities:** Actions performed by injected control code are often unlogged, aiding in non-repudiation issues.

## Common Consequences

* **Execute Unauthorized Code:** Full alteration of application logic and control flow.
* **Gain Privileges:** Accessing resources the attacker is otherwise prevented from reaching.
* **Bypass Access Control:** Modifying authentication or authorization routines.

## Likelihood of Exploit

**Medium**
While highly impactful, finding a direct "sink" that parses code (like `eval()`) is becoming less common in modern, well-architected systems.

## How This Is Typically Detected

* **Automated Static Analysis (SAST):** Tools model data and control flow to find patterns connecting untrusted "sources" (user input) to code-parsing "sinks" (e.g., `eval()`, `exec()`, `PHP assert()`). (Effectiveness: High).
* **Automated Dynamic Analysis:** Using fuzz testing and fault injection to send diverse inputs and monitor for unstable behavior or unauthorized command results. (Effectiveness: High).
* **Manual Review:** Assessing any functionality that involves dynamic calculation, template rendering, or formula parsing.

## Potential Mitigations

* **Refactor Logic (Primary):** Re-architect the program to eliminate the need for dynamically generated code.
* **Input Validation (Allowlist):** Use stringent allowlists to limit constructs. Note that alphanumeric checks are often insufficient, as attackers may reference dangerous built-in functions like `system()`, `exec()`, or `exit()`.
* **Sandbox or Jail:** Run code in environments like **Unix chroot** or **AppArmor** to enforce strict boundaries between the process and the OS.
* **Language-Specific Alternatives:**
* **Python:** Avoid `eval()`. While `ast.literal_eval()` is safer, it is still discouraged for untrusted data as it can lead to DoS via memory exhaustion through deeply nested structures.


* **Environment Hardening:** Use automatic taint propagation (e.g., **Perl's -T switch**) to prevent tainted variables from reaching execution sinks.

## Simplified Example

```python
# VULNERABLE: Direct evaluation of user input
user_input = "os.system('rm -rf /')"
eval(user_input) # Executes arbitrary system command

# SECURE: Use a mapping (Enforcement by Conversion) to avoid evaluation
def add(a, b): return a + b
def subtract(a, b): return a - b

ops = {"add": add, "sub": subtract}
selected_op = request.args.get("operation")
if selected_op in ops:
    result = ops[selected_op](10, 5)

```

## References

* [REF-44] 24 Deadly Sins of Software Security: Web-Client Related Vulnerabilities
* [REF-1373] Python Documentation: ast.literal_eval constraints
* [REF-183] Proper Validation of Input