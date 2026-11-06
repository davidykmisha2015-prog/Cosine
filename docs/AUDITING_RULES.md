# Cosine SAST Auditing Rules & Philosophy (Zero False Positives)

> **Primary Objective:** Rigorous intellectual honesty, independent critical thinking, and zero tolerance for false positives. In production and enterprise open-source environments, false positives erode developer trust, generate noise, and waste valuable engineering time.

---

## 1. Intellectual Honesty & Professional Skepticism

- **AI Must Exercise Its Own Judgment:** The SAST engine must never act like a panicked or superficial checklist scanner that invents problems just to "look thorough" or justify its execution.
- **A Clean Report `[]` is the Best Result:** When the analyzed code is secure, respects sound architecture, or employs proper validation, the AI is expected and required to return `[]`.
- **A Standard Bug ≠ A Security Vulnerability:** Unused variables, harmless syntax quirks, suboptimal idioms, minor string-formatting discrepancies (e.g., an extra unused argument in `string.format`), or general code smells must **never** be reported as security vulnerabilities.

---

## 2. Realistic Threat Modeling (CLI Tools vs. Network Services)

- **Self-Exploitation is NOT a Vulnerability:**
  - In CLI applications, the user executes the binary under their own local operating system account and privilege level.
  - If an "exploit" requires the local user to maliciously modify their own environment variables (e.g., `$HOME`, `$USER`, `$PATH`) or edit their own configuration files to compromise themselves, **this is not a vulnerability**.
- **Standard Operating System Paths:**
  - Reading `$HOME`, checking common directories (e.g., `Documents`, localized folders), or loading user configs from `~/.config` is standard, benign behavior for local CLI tools—not "Insecure File System Access".
  - A finding is only valid if **untrusted external data from an attacker** reaches a sensitive sink without appropriate validation.

---

## 3. Strict Source-to-Sink Dataflow Traceability

To legitimately flag a vulnerability, the engine must verify an unbroken, end-to-end dataflow path:

1. **Source:** Untrusted external input (unvalidated command-line parameters from an untrusted source, network socket, untrusted file).
2. **Missing or Flawed Sanitization:** The total absence of validation or an inherently broken check. If the code verifies against directory traversal (e.g., checks for `/`, `..`, or uses a character allowlist), **the engine must respect this boundary and refrain from raising an alert!**
3. **Sink:** A sensitive runtime primitive (`os.execute`, `subprocess(shell=True)`, `io.popen`, `loadstring`, arbitrary file writes or removals).

*If any link in this chain is absent or broken, no vulnerability exists.*

---

## 4. Prohibition of Hallucinations and Speculative Claims

- **Verify Exact Runtime Semantics:**
  - If a function call like `string.format('find "dir" -name "*.md"', arg)` is made, but the format string contains **no** format specifiers (e.g., `%s`), the argument is **not** interpolated into the string. The engine must not hallucinate a command injection.
- **Benign Read Operations:**
  - Reading a static, relative, or bounded local file (`io.open(path, "r")` or `open(path, "r")`) is not path traversal. Path traversal requires external input capable of escaping the intended boundary directory.
- **Parameterized Database Queries:**
  - Prepared statements and parameterized SQL queries (`cursor.execute(sql, (param,))`) are immune to SQL injection and must never be reported.

---

## 5. Severity Scale & Classification

| Level | Criteria | Example |
|---|---|---|
| **CRITICAL** | Direct Arbitrary Code Execution (RCE) via untrusted external input | Unsanitized concatenation of external input into `os.execute` or `pickle.loads` |
| **HIGH** | Arbitrary shell execution or arbitrary file write to system paths | Unvalidated filename in `io.popen` or unverified write to sensitive directories |
| **MEDIUM** | Verified logical authorization or state bypasses | Authentication or permission bypass in multi-user contexts |
| **LOW** | Genuine data leakage or hardcoded sensitive credentials | Real production API keys or tokens (not default configs or placeholders) |

*If a theoretical edge case poses no practical risk in the application's actual operational context, it must be rejected.*
