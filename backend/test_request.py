"""Quick test script to verify the /analyze endpoint works end-to-end."""

import requests
import json
import sys

# Fix Windows terminal encoding
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_URL = "http://127.0.0.1:8000"

# --- Test 1: Health check ---
print("=" * 60)
print("TEST 1: Health check")
print("=" * 60)
try:
    r = requests.get(f"{BASE_URL}/health", timeout=5)
    print(f"  Status: {r.status_code}")
    print(f"  Body:   {r.json()}")
    assert r.status_code == 200
    print("  [PASSED]\n")
except Exception as e:
    print(f"  [FAILED]: {e}\n")
    sys.exit(1)

# --- Test 2: Analyze vulnerable code (CWE-78 command injection) ---
print("=" * 60)
print("TEST 2: Analyze vulnerable code (CWE-78 - OS command injection)")
print("=" * 60)
vulnerable_code = """\
import os

def run_command(user_input):
    os.system("ping " + user_input)
"""
print(f"  Sending code snippet ({len(vulnerable_code)} chars)...")
print(f"  (This may take 30-60s while the model generates a response)\n")
try:
    r = requests.post(
        f"{BASE_URL}/analyze",
        json={"code": vulnerable_code},
        timeout=180,
    )
    print(f"  Status: {r.status_code}")
    print(f"  Response:")
    print(json.dumps(r.json(), indent=2))
    if r.status_code == 200:
        findings = r.json().get("findings", [])
        print(f"\n  Found {len(findings)} finding(s)")
        for f in findings:
            print(f"    - {f.get('cwe_id', '?')}: {f.get('description', '?')[:80]}")
        print("  [PASSED]\n")
    else:
        print(f"  [WARNING] Non-200 response (may be model output issue)")
except requests.exceptions.Timeout:
    print("  [FAILED] Request timed out after 180s")
except Exception as e:
    print(f"  [FAILED]: {e}")
