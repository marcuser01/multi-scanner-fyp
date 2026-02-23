# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

## Description

The product fails to neutralize or incorrectly neutralizes user-controllable input before it is placed in output used as a web page. This allows attackers to inject executable code (JavaScript, HTML tags, etc.) into a victim's browser. The vulnerability violates the **Same-Origin Policy**, executing malicious script in the context of the server's domain.

### Types of XSS

* **Reflected XSS:** Malicious content is delivered via a link/request and immediately reflected back to the user.
* **Stored XSS:** Malicious content is permanently stored on the server (e.g., database) and served to users later.
* **DOM-based XSS:** Vulnerability exists in client-side code where the script processes user data and injects it back into the Document Object Model.

## Why This Matters (Security Impact)

XSS allows attackers to bypass access controls and perform:

* **Session Hijacking:** Stealing session cookies and authentication tokens.
* **Unauthorized Execution:** Running arbitrary code on the victim's computer ("drive-by hacking").
* **Phishing/Defacement:** Modifying site presentation to trick users into revealing credentials.

## Common Consequences

* **Bypass Protection Mechanism:** Disclosing private information stored in cookies.
* **Read Application Data:** Accessing sensitive user data or site resources.
* **Integrity/Availability Loss:** Modifying content or redirecting users to malicious sites.

## Likelihood of Exploit

**High**
XSS vulnerabilities are widely understood, easy to exploit, and frequently targeted in real-world attacks.

## How This Is Typically Detected

* **Automated Static Analysis (SAST):** Tools like **Semgrep** use data flow analysis to identify unsanitized input reaching web output. (Effectiveness: Moderate).
* **Black Box Testing (DAST):** Using XSS Cheat Sheets or automated fuzzing to inject payloads and observe execution. (Effectiveness: Moderate).

## Potential Mitigations

* **Output Encoding:** Use context-aware encoding (HTML body, attributes, URIs, JavaScript, CSS). Entity encoding is only for the HTML body.
* **Vetted Libraries:** Use frameworks like **Microsoft Anti-XSS**, **OWASP ESAPI**, or **Apache Wicket** that provide built-in protection.
* **Input Validation:** Implement "accept known good" (allowlist) validation. Strictly define expected length, type, and syntax.
* **Content Security Policy (CSP):** Enforce a CSP to limit the sources from which scripts can be executed.
* **HttpOnly Cookies:** Set the `HttpOnly` flag on session cookies to prevent access via `document.cookie`.
* **Parameterization:** Use structured mechanisms that separate data from code automatically.

## Simplified Example

```python
# VULNERABLE: Direct insertion of untrusted data
user_input = "<script>alert('XSS')</script>"
return "<div>" + user_input + "</div>"

# SECURE: Context-aware output encoding
import html
user_input = "<script>alert('XSS')</script>"
return "<div>" + html.escape(user_input) + "</div>"

```

## References

* [REF-724] OWASP XSS Prevention Cheat Sheet
* [REF-714] RSnake XSS Cheat Sheet
* [REF-715] Mitigating XSS with HTTP-only Cookies
* [REF-45] OWASP Enterprise Security API (ESAPI)
