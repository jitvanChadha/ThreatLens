"""
Verification script for RAG and Vectorized Knowledge Base in ThreatLens.
"""

import sys
import json
import requests

# Fix Windows terminal encoding
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_URL = "http://127.0.0.1:8000"

def test_kb():
    print("=" * 60)
    print("TEST 1: Check KB Status")
    print("=" * 60)
    r = requests.get(f"{BASE_URL}/kb/status", timeout=10)
    print(f"Status: {r.status_code}")
    print(f"Body:   {r.json()}")
    assert r.status_code == 200

    print("\n" + "=" * 60)
    print("TEST 2: Manual Index Sample File")
    print("=" * 60)
    sample_code = """
import sqlite3

def query_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL query vulnerable to injection
    query = f"SELECT * FROM accounts WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()
"""
    files = {"files": ("test_sample_sql.py", sample_code, "text/x-python")}
    r = requests.post(f"{BASE_URL}/kb/index", files=files, timeout=30)
    print(f"Status: {r.status_code}")
    print(f"Body:   {r.json()}")
    assert r.status_code == 200

    print("\n" + "=" * 60)
    print("TEST 3: Semantic Search in KB")
    print("=" * 60)
    r = requests.get(f"{BASE_URL}/kb/search", params={"q": "SQL injection database query", "n": 3}, timeout=30)
    print(f"Status: {r.status_code}")
    results = r.json()
    print(f"Found {len(results)} hit(s):")
    for hit in results:
        print(f"  - [{hit.get('collection')}] {hit.get('filename')} (dist: {hit.get('distance'):.4f})")
    assert r.status_code == 200

    print("\n[ALL KB TESTS PASSED]")

if __name__ == "__main__":
    test_kb()
