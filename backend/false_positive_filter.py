"""
Deterministic False-Positive Filter for ThreatLens.

Filters out hallucinated or false-positive findings produced by the LLM:
1. CWE-89 (SQL Injection) flagged on parameterized queries:
   - cursor.execute("... %s ...", (param,))
   - cursor.execute("... ? ...", [param])
   - cursor.execute("... :param ...", {"param": value})
2. CWE-89 flagged on cursor housekeeping methods:
   - cursor.fetchall(), cursor.fetchone(), cursor.fetchmany(), cursor.close(), etc.
3. Findings where the recommended remediation code in 'fix' is ALREADY present
   in the source code at that location.
4. Findings pointing purely to blank or comment lines.
"""

import ast
import re
from typing import List, Dict, Any


def _normalize_snippet(s: str) -> str:
    """Normalize quotes and whitespace for comparison."""
    s = s.replace("'", '"')
    return re.sub(r"\s+", "", s)


def _is_safe_sql_statement(code_snippet: str) -> bool:
    """
    Returns True if the code snippet is demonstrably safe from SQL injection:
    - Pure fetch / cursor maintenance (fetchall, fetchone, etc.)
    - Properly parameterized cursor.execute() call
    """
    cleaned = code_snippet.strip()
    if not cleaned:
        return True

    # 1. Check for fetch / cursor maintenance methods
    if re.search(r"\b(?:fetchall|fetchone|fetchmany|close|commit|rollback)\s*\(", cleaned):
        return True

    # 2. Check via Python AST if possible
    try:
        tree = ast.parse(cleaned)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                attr_name = node.func.attr
                if attr_name in ("fetchall", "fetchone", "fetchmany", "close", "commit", "rollback"):
                    return True
                if attr_name in ("execute", "executemany"):
                    # Must have at least 2 arguments: query and params
                    if len(node.args) >= 2:
                        query_arg = node.args[0]
                        params_arg = node.args[1]
                        # Safe if query_arg is a static string literal without string formatting
                        if isinstance(query_arg, ast.Constant) and isinstance(query_arg.value, str):
                            if isinstance(params_arg, (ast.Tuple, ast.List, ast.Dict, ast.Name)):
                                return True
    except Exception:
        pass

    # 3. Heuristic regex fallback for parameterized execute calls
    if re.search(r"\.execute(?:many)?\s*\(\s*[\"'][^\"']*(?:%s|\?|:\w+)[^\"']*[\"']\s*,\s*[\(\[\{A-Za-z_]", cleaned):
        first_arg = cleaned.split(",", 1)[0]
        # Ensure first arg doesn't contain string formatting / concatenation
        if not re.search(r"[\"']\s*[+%]|\.format\s*\(|f[\"']", first_arg):
            return True

    return False


def _fix_already_present(fix_text: str, code_lines: List[str], start: int, end: int) -> bool:
    """
    Returns True if the specific remediation code suggested in 'fix'
    is already present in the target code snippet (within +- 3 lines).
    """
    if not fix_text:
        return False

    # Extract code portion from fix: e.g. `cur.execute(...)` or after colon
    code_matches = re.findall(r"[`'\"]([^`'\"]{10,})[`'\"]", fix_text)
    colon_match = re.search(r":\s*([a-zA-Z_]\w*\.[a-zA-Z_]\w*\(.*?\))", fix_text)
    if colon_match:
        code_matches.append(colon_match.group(1))

    if not code_matches:
        return False

    window_start = max(0, start - 4)
    window_end = min(len(code_lines), end + 3)
    target_block = "".join(code_lines[window_start:window_end])
    norm_target = _normalize_snippet(target_block)

    for cand in code_matches:
        norm_cand = _normalize_snippet(cand)
        if len(norm_cand) > 12 and norm_cand in norm_target:
            return True

    return False


def _is_comment_or_empty(lines: List[str]) -> bool:
    """Returns True if all lines in the list are comments or empty."""
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#") and not s.startswith('"""') and not s.startswith("'''"):
            return False
    return True


def filter_false_positives(findings: List[Dict[str, Any]], code: str) -> List[Dict[str, Any]]:
    """
    Post-process findings list to remove evident false positives.
    """
    code_lines = code.splitlines(keepends=True)
    filtered = []

    for f in findings:
        cwe = (f.get("cwe_id") or "").upper()
        start = f.get("line_start", 1)
        end = f.get("line_end", start)
        fix = f.get("fix", "")

        # Target lines in 0-indexed bounds
        idx_start = max(0, start - 1)
        idx_end = min(len(code_lines), max(start, end))
        target_snippet_lines = code_lines[idx_start:idx_end]
        target_snippet = "".join(target_snippet_lines).strip()

        # 1. Filter out pure comments or blank lines
        if _is_comment_or_empty(target_snippet_lines):
            continue

        # 2. Filter out CWE-89 (SQL Injection) false positives on safe / parameterized queries
        if cwe == "CWE-89" or "SQL" in (f.get("vulnerability") or "").upper():
            if _is_safe_sql_statement(target_snippet):
                continue

        # 3. Filter out findings where the suggested fix is already implemented
        if _fix_already_present(fix, code_lines, start, end):
            continue

        filtered.append(f)

    return filtered
