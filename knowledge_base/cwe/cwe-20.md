# CWE-20: Improper Input Validation

## Description

The product receives input or data, but it does not validate or incorrectly validates that the input has the properties required to process the data safely and correctly. Input validation ensures that potentially dangerous inputs are safe for processing within the code or when communicating with other components.

## What Qualifies as Input?

Input is not just user-typed text. It enters the application through many vectors:

* **Raw Data:** Strings, numbers, parameters, and file contents.
* **Metadata:** Information about the data, such as headers, file sizes, or character encoding.
* **Entry Points:** Parameters, cookies, network reads, environment variables, reverse DNS lookups, query results, e-mail, and external database feeds.

## Why This Matters (Security Impact)

Input validation is a foundational security layer. Without it, the application assumes all data follows business rules and safety constraints.

* **Execute Unauthorized Code:** Malicious input can alter control flow or inject commands (e.g., SQL Injection, OS Command Injection).
* **Denial of Service (DoS):** Unexpected values can cause crashes or trigger excessive consumption of CPU and memory.
* **Information Disclosure:** Controlling resource references (like file paths) can allow an attacker to read confidential files or memory.

## Key Properties to Validate

Effective validation checks more than just "bad characters." It must verify:

* **Quantities:** Size, length, frequency, price, and rate.
* **Syntax:** Well-formedness and compliance with expected rules.
* **Type:** The actual data type (e.g., ensuring a string is actually a number).
* **Consistency:** Logic checks between multiple fields (e.g., "start date" must be before "end date").
* **Domain Rules:** Business logic (e.g., "boat" is a valid string but not a valid "color").

## Likelihood of Exploit

**High**
Since almost every application feature requires input, this is the most common attack surface exploited by adversaries.

## How This Is Typically Detected

* **Fuzzing:** Highly effective. Providing random or algorithmic inputs to find crashes or unhandled exceptions. (Effectiveness: High).
* **Automated Static Analysis (SAST):** Scans source code for missing validation checks or the use of unsafe "sinks." (Effectiveness: High).
* **Manual Review:** Necessary for complex business logic that automated tools cannot understand. (Effectiveness: High).
* **Dynamic Scanners (DAST):** Web and database scanners that interact with the running application to find bypasses. (Effectiveness: High).

## Potential Mitigations

### Architecture and Design

* **Language-Theoretic Security (LangSec):** Use formal "recognizers" to parse input as a distinct layer before it reaches internal logic.
* **Use Frameworks:** Employ vetted libraries like **OWASP ESAPI Validation API** or **Struts**.
* **Server-Side Checks:** Always duplicate client-side checks on the server. Client-side checks are for UX; server-side checks are for security.

### Implementation

* **Strategy: "Accept Known Good":** Use an **allowlist** of acceptable inputs. Reject anything that doesn't strictly conform. Avoid relying solely on "denylists" (looking for bad characters).
* **Canonicalization:** Decode and simplify input to its most basic form before validating to prevent "double-decoding" bypasses.
* **Type Conversion:** Directly convert input into the expected type (e.g., `int()`) immediately after receipt.
* **Validate After Combining:** If data comes from multiple sources, re-validate it once it is combined.

## Simplified Example

```python
# VULNERABLE: Direct use of input in a sensitive operation
def delete_profile(user_id):
    # What if user_id is "1 OR 1=1"?
    db.execute(f"DELETE FROM users WHERE id = {user_id}")

# SECURE: Strict input validation using an allowlist and type conversion
def delete_profile(user_id):
    try:
        # 1. Type Validation: Ensure it's a number
        safe_id = int(user_id)
        # 2. Range Validation: Ensure it's a positive ID
        if safe_id <= 0:
            raise ValueError("Invalid ID")
        # 3. Use Parameterized Query
        db.execute("DELETE FROM users WHERE id = ?", (safe_id,))
    except ValueError:
        log_security_event("Malformed input detected")
        return "Error", 400

```

## Important Note: Validation vs. Escaping

Input validation is **not** output escaping. Validation checks if data is "sane." Escaping ensures that data (even "sane" data like the name "O'Reilly") is not misinterpreted by the next component (like a SQL database). You often need both.

## References

* [REF-7] Writing Secure Code: All Input Is Evil!
* [REF-1111] Curing the Vulnerable Parser (LangSec)
* [REF-45] OWASP ESAPI Project
* [REF-1287] MITRE: Problematic Mappings in Top 25
