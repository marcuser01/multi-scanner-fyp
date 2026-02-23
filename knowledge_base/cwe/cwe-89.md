# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

## Description

The product constructs an SQL command using externally-influenced input but fails to neutralize special elements. This allows attackers to modify the intended logic of the SQL query. By injecting SQL syntax into user-controllable fields, inputs are interpreted as commands rather than data, enabling unauthorized database interaction.

## Why This Matters (Security Impact)

SQL Injection (SQLi) is critical because it provides a direct gateway to the data layer. Attackers can:

* **Execute Unauthorized Commands:** Redirect database output to files or execute system-level commands.
* **Bypass Authentication:** Connect as administrative users without knowing passwords by manipulating login queries.
* **Modify Permissions:** Alter authorization tables to escalate privileges or change access control logic.

## Common Consequences

* **Read Application Data:** Massive disclosure of sensitive information stored in the database.
* **Modify Application Data:** Unauthorized insertion, update, or deletion of records (Integrity loss).
* **Identity Theft:** Assuming the identity of other users by bypassing protection mechanisms.

## Likelihood of Exploit

**High**
SQLi is a foundational web vulnerability. It is well-documented, easily automated with tools (like sqlmap), and results in high-impact compromises.

## How This Is Typically Detected

* **Automated Static Analysis (SAST):** Tools like **Semgrep** identify data flow where untrusted variables reach "sink" functions (e.g., `execute()`) without parameterization. (Effectiveness: High).
* **Automated Dynamic Analysis (DAST):** Fuzzing inputs with SQL meta-characters to trigger database errors or behavioral changes. (Effectiveness: High).
* **Manual Code Review:** Focused inspection of database abstraction layers and manual spot-checks of query construction. (Effectiveness: High).

## Potential Mitigations

* **Parameterization (Primary):** Use **Prepared Statements** or **Parameterized Queries**. These mechanisms separate code from data, ensuring inputs are treated strictly as literals.
* **Vetted Frameworks:** Utilize persistence layers (e.g., **Hibernate**, **Entity Framework**) that handle query building safely by default.
* **Principle of Least Privilege:** Run database accounts with minimal necessary permissions; avoid using 'sa' or 'root' accounts for application logic.
* **Input Validation:** Implement an "allowlist" strategy for all inputs (type, length, and format). Note: This is defense-in-depth and does not replace parameterization.
* **Output Encoding:** If dynamic queries are unavoidable, use database-specific escaping functions (e.g., `mysql_real_escape_string()`).
* **Error Management:** Suppress detailed database error messages in production to prevent leaking query structure to attackers.

## Simplified Example

```python
# VULNERABLE: String formatting allows SQL syntax injection
cursor.execute("SELECT * FROM users WHERE username = '%s'" % user_input)

# SECURE: Parameterized query separates data from command
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))

```

## References

* [REF-867] OWASP SQL Injection Prevention Cheat Sheet
* [REF-1447] CISA Alert: Eliminating SQL Injection in Software
* [REF-44] 24 Deadly Sins of Software Security: SQL Injection
* [REF-1482] D3FEND: Trusted Library (D3-TL)
