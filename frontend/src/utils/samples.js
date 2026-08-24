export const SAMPLES = [
  {
    id: 'cmd-injection',
    title: 'Command Injection (CWE-78)',
    cwe: 'CWE-78',
    description: 'Unsanitized input passed directly to os.system()',
    code: `import os

def ping_host(user_supplied_host):
    # Vulnerable: command injection via unsanitized input
    cmd = "ping -c 1 " + user_supplied_host
    os.system(cmd)

if __name__ == "__main__":
    host = "127.0.0.1; cat /etc/passwd"
    ping_host(host)
`,
  },
  {
    id: 'sqli',
    title: 'SQL Injection (CWE-89)',
    cwe: 'CWE-89',
    description: 'Direct string concatenation in raw SQL database query',
    code: `import sqlite3

def get_user_profile(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Vulnerable: SQL injection via string formatting
    query = f"SELECT id, username, email FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    
    return cursor.fetchall()
`,
  },
  {
    id: 'path-traversal',
    title: 'Path Traversal (CWE-22)',
    cwe: 'CWE-22',
    description: 'Direct file path concatenation without directory traversal validation',
    code: `import os

BASE_DIR = "/var/www/uploads"

def download_file(filename):
    # Vulnerable: path traversal allows reading arbitrary files like ../../etc/shadow
    file_path = os.path.join(BASE_DIR, filename)
    with open(file_path, "rb") as f:
        return f.read()
`,
  },
  {
    id: 'deserialization',
    title: 'Insecure Deserialization (CWE-502)',
    cwe: 'CWE-502',
    description: 'Unpickling untrusted payload leading to arbitrary code execution',
    code: `import pickle
import base64

def load_user_session(cookie_payload):
    # Vulnerable: pickle deserialization of untrusted user input
    raw_data = base64.b64decode(cookie_payload)
    session = pickle.loads(raw_data)
    return session
`,
  },
  {
    id: 'hardcoded-secrets',
    title: 'Hardcoded Credentials (CWE-798)',
    cwe: 'CWE-798',
    description: 'API keys, database passwords, or JWT secrets hardcoded in source',
    code: `import requests

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "SuperSecretPassword123!"

def connect_service():
    headers = {"Authorization": f"Bearer {AWS_SECRET_KEY}"}
    return requests.get("https://api.internal.corp/data", headers=headers)
`,
  },
  {
    id: 'ssrf',
    title: 'Server-Side Request Forgery (CWE-918)',
    cwe: 'CWE-918',
    description: 'Fetching user-provided URL without restricting internal IP ranges',
    code: `import requests

def fetch_external_avatar(user_avatar_url):
    # Vulnerable: SSRF allows requests to metadata endpoints (e.g. 169.254.169.254)
    response = requests.get(user_avatar_url, timeout=5)
    return response.content
`,
  },
  {
    id: 'safe-code',
    title: 'Clean / Safe Implementation',
    cwe: 'Clean',
    description: 'Parameterized queries and validated inputs with subprocess list syntax',
    code: `import subprocess
import sqlite3
import ipaddress

def ping_host_safe(ip_str):
    # Validate IP address before running command
    ip = ipaddress.ip_address(ip_str)
    result = subprocess.run(
        ["ping", "-c", "1", str(ip)],
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout

def get_user_profile_safe(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Parameterized query protects against SQL injection
    cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()
`,
  },
];
