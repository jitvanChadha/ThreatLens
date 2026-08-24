"""
Deterministic regex-based security scanner — false-negative safety net.

Runs alongside the LLM to catch common vulnerability patterns that
the model might miss. Each rule is intentionally high-confidence
(simple, well-known patterns) to minimise false positives.

The regex scanner is NOT a replacement for the LLM — it's a baseline
coverage guarantee. The LLM still provides richer, context-aware analysis.
"""

import re
from dataclasses import dataclass
from typing import List


@dataclass
class RegexFinding:
    """Intermediate result from a regex rule, converted to a Finding later."""
    cwe_id: str
    vulnerability: str
    severity: str
    line_start: int
    line_end: int
    description: str
    fix: str


def to_finding_dict(rf: RegexFinding) -> dict:
    """Convert a RegexFinding to a dict compatible with the Finding schema."""
    return {
        "cwe_id": rf.cwe_id,
        "vulnerability": rf.vulnerability,
        "severity": rf.severity,
        "line_start": rf.line_start,
        "line_end": rf.line_end,
        "description": rf.description,
        "fix": rf.fix,
        "source": "regex",
    }


# ---------------------------------------------------------------------------
# Helper: check whether a line is inside a comment or docstring
# ---------------------------------------------------------------------------

def _is_comment_or_docstring_line(line: str) -> bool:
    """Very rough heuristic: skip lines that are pure comments or look like
    they belong to a docstring (start with triple-quotes or are indented
    text inside one). Doesn't do full AST parsing, but avoids the most
    obvious false-positive triggers from docstrings/comments."""
    stripped = line.strip()
    if stripped.startswith("#"):
        return True
    if stripped.startswith('"""') or stripped.startswith("'''"):
        return True
    return False


# ---------------------------------------------------------------------------
# Individual CWE rules
# ---------------------------------------------------------------------------

# CWE-78: OS Command Injection
_CMD_INJECTION_FUNCS = re.compile(
    r"\b(?:os\.system|os\.popen|subprocess\.call|subprocess\.Popen)\s*\(",
    re.IGNORECASE,
)
_SHELL_TRUE = re.compile(r"\bshell\s*=\s*True\b")
_CMD_CONCAT = re.compile(r"""[+]|\.format\s*\(|f['"]""")


def _check_cwe78(lines: List[str]) -> List[RegexFinding]:
    findings = []
    for i, line in enumerate(lines, 1):
        if _is_comment_or_docstring_line(line):
            continue
        if _CMD_INJECTION_FUNCS.search(line):
            # os.system / os.popen are always shell-based, flag directly
            if "os.system" in line or "os.popen" in line:
                findings.append(RegexFinding(
                    cwe_id="CWE-78",
                    vulnerability="OS Command Injection",
                    severity="high",
                    line_start=i, line_end=i,
                    description="User input may be concatenated into a shell command via "
                                f"{'os.system' if 'os.system' in line else 'os.popen'}(), "
                                "allowing arbitrary command execution.",
                    fix="Use subprocess.run() with a list of arguments and shell=False "
                        "to prevent injection.",
                ))
            # subprocess.call / Popen with shell=True + string concat
            elif _SHELL_TRUE.search(line) and _CMD_CONCAT.search(line):
                findings.append(RegexFinding(
                    cwe_id="CWE-78",
                    vulnerability="OS Command Injection",
                    severity="high",
                    line_start=i, line_end=i,
                    description="subprocess is called with shell=True and a dynamically "
                                "constructed command string, allowing command injection.",
                    fix="Use subprocess.run() with a list of arguments and shell=False.",
                ))
    return findings


# CWE-798: Hardcoded Credentials
_HARDCODED_CRED = re.compile(
    r"""(?:api[_-]?key|secret[_-]?key|password|passwd|token|auth[_-]?token|"""
    r"""access[_-]?key|private[_-]?key)\s*=\s*['"][^'"]{8,}['"]""",
    re.IGNORECASE,
)
# Exclude lines that load from env or config
_ENV_LOAD = re.compile(r"os\.environ|os\.getenv|config\.|settings\.", re.IGNORECASE)


def _check_cwe798(lines: List[str]) -> List[RegexFinding]:
    findings = []
    for i, line in enumerate(lines, 1):
        if _is_comment_or_docstring_line(line):
            continue
        if _HARDCODED_CRED.search(line) and not _ENV_LOAD.search(line):
            findings.append(RegexFinding(
                cwe_id="CWE-798",
                vulnerability="Hardcoded Credentials",
                severity="high",
                line_start=i, line_end=i,
                description="A secret value appears to be hardcoded in source code, "
                            "exposing it to anyone with repository access.",
                fix="Store secrets in environment variables or a secrets manager "
                    "and load them at runtime (e.g., os.environ['API_KEY']).",
            ))
    return findings


# CWE-89: SQL Injection
_SQL_KEYWORDS = re.compile(
    r"""['"]?\s*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b""",
    re.IGNORECASE,
)
_SQL_CONCAT = re.compile(r"""[+]|\.format\s*\(|f['"]|%\s""")
_PARAMETERIZED = re.compile(r"""%s|:\w+|\?\s*[,)]""")


def _check_cwe89(lines: List[str]) -> List[RegexFinding]:
    findings = []
    for i, line in enumerate(lines, 1):
        if _is_comment_or_docstring_line(line):
            continue
        if _SQL_KEYWORDS.search(line) and _SQL_CONCAT.search(line):
            # Check it's not a parameterized query
            if not _PARAMETERIZED.search(line):
                findings.append(RegexFinding(
                    cwe_id="CWE-89",
                    vulnerability="SQL Injection",
                    severity="high",
                    line_start=i, line_end=i,
                    description="A SQL query appears to be constructed via string "
                                "concatenation or formatting with user-supplied input.",
                    fix="Use parameterized queries: cursor.execute("
                        "'SELECT * FROM users WHERE name = %s', (value,)).",
                ))
    return findings


# CWE-79: Cross-Site Scripting (XSS)
_DIRECT_HTML_RETURN = re.compile(
    r"""return\s+f['"].*<\w+.*\{.*\}.*>""",
)


def _check_cwe79(lines: List[str]) -> List[RegexFinding]:
    findings = []
    for i, line in enumerate(lines, 1):
        if _is_comment_or_docstring_line(line):
            continue
        if _DIRECT_HTML_RETURN.search(line):
            findings.append(RegexFinding(
                cwe_id="CWE-79",
                vulnerability="Cross-Site Scripting (XSS)",
                severity="high",
                line_start=i, line_end=i,
                description="User input is interpolated directly into an HTML response "
                            "without escaping, allowing script injection.",
                fix="Use a templating engine with auto-escaping (e.g., Jinja2's "
                    "render_template) or markupsafe.escape().",
            ))
    return findings


# CWE-22: Path Traversal
_FILE_ACCESS = re.compile(
    r"""\b(?:send_file|open)\s*\(""",
)
_BASENAME_GUARD = re.compile(r"os\.path\.basename|secure_filename")
_USER_INPUT_IN_PATH = re.compile(
    r"""request\.(?:args|form|values|json)\.get|request\.(?:args|form)\[""",
)


def _check_cwe22(lines: List[str]) -> List[RegexFinding]:
    findings = []
    for i, line in enumerate(lines, 1):
        if _is_comment_or_docstring_line(line):
            continue
        if _FILE_ACCESS.search(line):
            # Look at surrounding context (current line + 3 lines before)
            context_start = max(0, i - 4)
            context = "\n".join(lines[context_start:i])
            if _USER_INPUT_IN_PATH.search(context) and not _BASENAME_GUARD.search(context):
                findings.append(RegexFinding(
                    cwe_id="CWE-22",
                    vulnerability="Path Traversal",
                    severity="high",
                    line_start=i, line_end=i,
                    description="User-supplied filename is used in a file path without "
                                "validation, allowing access to files outside the intended "
                                "directory via sequences like '../'.",
                    fix="Use os.path.basename() to strip directory components, or validate "
                        "the resolved path starts with the intended base directory.",
                ))
    return findings


# CWE-502: Insecure Deserialization
_UNSAFE_DESERIALIZE = re.compile(
    r"""\b(?:pickle\.loads?|shelve\.open|marshal\.loads?|yaml\.(?:load|unsafe_load))\s*\(""",
)
_YAML_SAFE = re.compile(r"Loader\s*=\s*(?:yaml\.)?SafeLoader|yaml\.safe_load")


def _check_cwe502(lines: List[str]) -> List[RegexFinding]:
    findings = []
    for i, line in enumerate(lines, 1):
        if _is_comment_or_docstring_line(line):
            continue
        if _UNSAFE_DESERIALIZE.search(line):
            if "yaml" in line.lower() and _YAML_SAFE.search(line):
                continue
            findings.append(RegexFinding(
                cwe_id="CWE-502",
                vulnerability="Insecure Deserialization",
                severity="critical",
                line_start=i, line_end=i,
                description="Untrusted data is deserialized with a method that can "
                            "execute arbitrary code during unpickling/loading.",
                fix="Use a safe serialization format such as JSON. If pickle is "
                    "unavoidable, restrict loading to trusted sources and verify "
                    "data integrity with hmac.",
            ))
    return findings


# CWE-918: Server-Side Request Forgery (SSRF)
_REQUESTS_CALL = re.compile(
    r"""\brequests\.(?:get|post|put|patch|delete|head|options)\s*\(""",
)
_LITERAL_URL = re.compile(r"""requests\.\w+\s*\(\s*['"]https?://""")
_ALLOWLIST_CHECK = re.compile(
    r"ALLOWED|allowlist|whitelist|urlparse.*hostname", re.IGNORECASE,
)


def _check_cwe918(lines: List[str]) -> List[RegexFinding]:
    findings = []
    for i, line in enumerate(lines, 1):
        if _is_comment_or_docstring_line(line):
            continue
        if _REQUESTS_CALL.search(line) and not _LITERAL_URL.search(line):
            # Check context for an allowlist guard (5 lines before)
            context_start = max(0, i - 6)
            context = "\n".join(lines[context_start:i])
            if not _ALLOWLIST_CHECK.search(context):
                # Check if the URL comes from user input (request obj nearby)
                full_context = "\n".join(lines[context_start:i + 1])
                if _USER_INPUT_IN_PATH.search(full_context) or re.search(
                    r"request\.(?:form|args|json|data|values)", full_context
                ):
                    findings.append(RegexFinding(
                        cwe_id="CWE-918",
                        vulnerability="Server-Side Request Forgery (SSRF)",
                        severity="high",
                        line_start=i, line_end=i,
                        description="A user-supplied URL is fetched by the server without "
                                    "validation, allowing access to internal services.",
                        fix="Validate and allowlist target URLs/domains. Block private/internal "
                            "IP ranges and metadata endpoints (e.g., 169.254.169.254).",
                    ))
    return findings


# CWE-327: Weak Cryptography
_WEAK_HASH = re.compile(
    r"""\bhashlib\.(?:md5|sha1)\s*\(""",
)


def _check_cwe327(lines: List[str]) -> List[RegexFinding]:
    findings = []
    for i, line in enumerate(lines, 1):
        if _is_comment_or_docstring_line(line):
            continue
        if _WEAK_HASH.search(line):
            algo = "MD5" if "md5" in line else "SHA1"
            findings.append(RegexFinding(
                cwe_id="CWE-327",
                vulnerability="Use of a Broken or Risky Cryptographic Algorithm",
                severity="high",
                line_start=i, line_end=i,
                description=f"{algo} is used for hashing. {algo} is cryptographically "
                            "broken and unsuitable for security-sensitive operations.",
                fix="Use a modern password-hashing algorithm such as bcrypt, scrypt, "
                    "or argon2 (e.g., bcrypt.hashpw()).",
            ))
    return findings


# CWE-330: Insecure Randomness
_INSECURE_RANDOM = re.compile(
    r"""\brandom\.(?:randint|random|choices|choice|sample|uniform|getrandbits)\s*\(""",
)
_SECURITY_CONTEXT_FUNC = re.compile(
    r"""def\s+\w*(?:token|secret|reset|password|otp|nonce|key|session|auth)\w*\s*\(""",
    re.IGNORECASE,
)


def _check_cwe330(lines: List[str]) -> List[RegexFinding]:
    findings = []
    # Track whether we're inside a security-relevant function
    in_security_func = False
    func_indent = 0

    for i, line in enumerate(lines, 1):
        if _is_comment_or_docstring_line(line):
            continue

        # Detect security-relevant function definitions
        m = _SECURITY_CONTEXT_FUNC.search(line)
        if m:
            in_security_func = True
            func_indent = len(line) - len(line.lstrip())
            continue

        # Reset when we leave the function (dedent)
        if in_security_func and line.strip() and not line.startswith(" " * (func_indent + 1)):
            if not line[func_indent:func_indent + 1].isspace() and line.strip():
                # Check if it's a new top-level def/class — reset context
                if line.strip().startswith(("def ", "class ", "@")):
                    in_security_func = False

        if _INSECURE_RANDOM.search(line):
            if in_security_func:
                findings.append(RegexFinding(
                    cwe_id="CWE-330",
                    vulnerability="Use of Insufficiently Random Values",
                    severity="medium",
                    line_start=i, line_end=i,
                    description="The standard random module uses a predictable PRNG. "
                                "Tokens generated this way can be guessed by an attacker.",
                    fix="Use the secrets module for security-sensitive randomness: "
                        "secrets.token_urlsafe() or secrets.token_hex().",
                ))

    return findings


# CWE-20: Improper Input Validation
_DIRECT_CAST = re.compile(
    r"""\b(?:float|int)\s*\(\s*(?:request\.(?:args|form|values|json)"""
    r"""\.get\s*\(|request\.(?:args|form)\[)""",
)
_TRY_GUARD = re.compile(r"^\s*try\s*:")


def _check_cwe20(lines: List[str]) -> List[RegexFinding]:
    findings = []
    for i, line in enumerate(lines, 1):
        if _is_comment_or_docstring_line(line):
            continue
        if _DIRECT_CAST.search(line):
            # Check if there's a try: block in the 3 lines above
            context_start = max(0, i - 4)
            context = "\n".join(lines[context_start:i])
            if not _TRY_GUARD.search(context):
                findings.append(RegexFinding(
                    cwe_id="CWE-20",
                    vulnerability="Improper Input Validation",
                    severity="medium",
                    line_start=i, line_end=i,
                    description="User input is cast directly without validation, "
                                "allowing invalid values (negative, NaN, Inf) into "
                                "sensitive operations.",
                    fix="Validate and sanitize input before use: check that the value "
                        "is a positive finite number within an acceptable range.",
                ))
    return findings


# ---------------------------------------------------------------------------
# Main scanner entry point
# ---------------------------------------------------------------------------

_ALL_CHECKS = [
    _check_cwe78,
    _check_cwe798,
    _check_cwe89,
    _check_cwe79,
    _check_cwe22,
    _check_cwe502,
    _check_cwe918,
    _check_cwe327,
    _check_cwe330,
    _check_cwe20,
]


def regex_scan(code: str) -> list[dict]:
    """
    Run all regex-based rules against the given source code.
    Returns a list of Finding-compatible dicts with source='regex'.
    """
    lines = code.splitlines()
    results = []
    for check_fn in _ALL_CHECKS:
        for rf in check_fn(lines):
            results.append(to_finding_dict(rf))
    return results


# ---------------------------------------------------------------------------
# Merge logic: combine LLM + regex findings, deduplicate
# ---------------------------------------------------------------------------

def _findings_overlap(a: dict, b: dict) -> bool:
    """True if two findings share the same CWE and have overlapping or adjacent line ranges (within 3 lines)."""
    if a["cwe_id"] != b["cwe_id"]:
        return False
    # Check line range overlap or proximity within 3 lines
    overlap = (a["line_start"] <= b["line_end"] and b["line_start"] <= a["line_end"])
    close_distance = (
        abs(a["line_start"] - b["line_start"]) <= 3 or
        abs(a["line_end"] - b["line_end"]) <= 3
    )
    return overlap or close_distance


def merge_findings(llm_findings: list[dict], regex_findings: list[dict]) -> list[dict]:
    """
    Merge LLM and regex findings. LLM findings take priority (richer
    descriptions). Regex findings are added only if the LLM didn't
    already catch the same issue (same CWE + overlapping line range).
    """
    # Convert LLM findings to dicts if they aren't already
    llm_dicts = []
    for f in llm_findings:
        if hasattr(f, "model_dump"):
            d = f.model_dump()
            d.setdefault("source", "llm")
            llm_dicts.append(d)
        elif isinstance(f, dict):
            f.setdefault("source", "llm")
            llm_dicts.append(f)

    # Add regex findings that the LLM missed
    for rf in regex_findings:
        already_covered = any(_findings_overlap(rf, lf) for lf in llm_dicts)
        if not already_covered:
            llm_dicts.append(rf)

    # Sort by line_start for consistent output
    llm_dicts.sort(key=lambda f: f.get("line_start", 0))
    return llm_dicts
