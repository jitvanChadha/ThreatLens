"""
Client for the Context7 REST API.

Automatically parses library imports from user code and queries
Context7 to fetch version-specific documentation and security guidelines.
"""

import ast
import os
import logging
from typing import List, Set
import requests

logger = logging.getLogger("context7")

# --- Configuration ---
# Paste your Context7 API key here directly, or set the CONTEXT7_API_KEY environment variable.
CONTEXT7_API_KEY = ""

# Known third-party libraries we want to check for security docs
SUPPORTED_LIBS = {
    "flask",
    "requests",
    "pickle",
    "yaml",
    "cryptography",
    "bcrypt",
    "random",
    "hashlib",
    "sqlite3",
    "pymysql",
    "psycopg2",
    "subprocess",
    "os",
}


def extract_imports(code: str) -> Set[str]:
    """Parse python code and return top-level imported module names."""
    imported = set()
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imported.add(name.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module.split(".")[0])
    except Exception as e:
        logger.warning(f"Failed to parse imports via AST: {e}")
        # Simple regex fallback if AST fails
        import re
        matches = re.findall(r"^\s*(?:import|from)\s+(\w+)", code, re.MULTILINE)
        imported.update(matches)

    # Filter to only check libs we know might have security context
    return imported.intersection(SUPPORTED_LIBS)


def get_context7_docs(code: str) -> str:
    """
    Find library imports, query Context7 for security context/docs on those libraries,
    and return a consolidated string. Fallback gracefully if no key is present or request fails.
    """
    api_key = os.environ.get("CONTEXT7_API_KEY") or CONTEXT7_API_KEY
    if not api_key:
        logger.debug("CONTEXT7_API_KEY not set. Skipping Context7 lookup.")
        return ""

    libs = extract_imports(code)
    if not libs:
        return ""

    headers = {
        "Authorization": f"Bearer {api_key}"
    }
    base_url = "https://context7.com/api"
    collected_docs = []

    for lib in libs:
        try:
            logger.info(f"Querying Context7 for library: {lib}")
            # Search for library guidelines/documentation
            params = {
                "libraryName": lib,
                "query": "security best practices vulnerabilities safe use",
            }
            resp = requests.get(
                f"{base_url}/v2/libs/search",
                headers=headers,
                params=params,
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                # Check for document snippets in response
                # Depending on API structure, parse results or hits
                results = data.get("results", []) or data.get("hits", []) or data.get("data", [])
                if isinstance(results, list) and results:
                    snippets = []
                    for doc in results[:3]:  # Top 3 relevant snippets
                        if isinstance(doc, dict):
                            content = doc.get("content") or doc.get("snippet") or doc.get("text")
                            if content:
                                snippets.append(content.strip())
                    if snippets:
                        collected_docs.append(
                            f"--- Library: {lib} ---\n" + "\n\n".join(snippets)
                        )
            else:
                logger.warning(
                    f"Context7 returned status code {resp.status_code} for {lib}: {resp.text}"
                )
        except Exception as e:
            logger.warning(f"Error querying Context7 for {lib}: {e}")

    if collected_docs:
        return "\n\n".join(collected_docs)
    return ""
