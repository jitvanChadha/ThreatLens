import { useState } from 'react';
import { PenLine, Copy, Check, ArrowRight } from 'lucide-react';

const PRESET_TEMPLATES = [
  {
    title: 'Hardened Subprocess Runner',
    category: 'Command Injection Defense',
    prompt: 'Write a secure subprocess wrapper in Python that avoids shell=True and validates arguments.',
    code: `import subprocess

def execute_hardened_cmd(binary_path: str, user_args: list[str]) -> str:
    """
    Safely executes a binary with isolated arguments.
    Never passes through a system shell interpreter (prevents CWE-78).
    """
    # Validate binary exists in approved allowlist
    ALLOWED_BINARIES = {"/usr/bin/ping", "/bin/echo", "/usr/bin/git"}
    if binary_path not in ALLOWED_BINARIES:
        raise ValueError(f"Unauthorized binary execution attempt: {binary_path}")
    
    cmd_list = [binary_path] + [str(arg) for arg in user_args]
    
    # Run with check=True and shell=False (default)
    result = subprocess.run(
        cmd_list,
        capture_output=True,
        text=True,
        check=True,
        timeout=10
    )
    return result.stdout
`,
  },
  {
    title: 'Secure Parameterized SQL DAO',
    category: 'SQL Injection Defense',
    prompt: 'Create a safe SQLite database helper using parameterized positional placeholders.',
    code: `import sqlite3
from typing import Optional, Any

class SecureUserDAO:
    def __init__(self, db_path: str = "app.db"):
        self.db_path = db_path

    def get_user_by_id(self, user_id: int) -> Optional[dict[str, Any]]:
        # Strictly parameterized query: user_id is passed in tuple, never formatted
        query = "SELECT id, username, email, role FROM users WHERE id = ? LIMIT 1;"
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (int(user_id),))
            row = cursor.fetchone()
            return dict(row) if row else None
`,
  },
  {
    title: 'Path Traversal Guard',
    category: 'Path Traversal Defense',
    prompt: 'Write a safe file downloader ensuring target paths cannot escape the base directory.',
    code: `from pathlib import Path

BASE_STORAGE_DIR = Path("/var/app/storage").resolve()

def safe_read_file(user_filename: str) -> bytes:
    """
    Sanitizes and resolves relative file paths to guarantee
    no traversal outside BASE_STORAGE_DIR (prevents CWE-22).
    """
    if "\\0" in user_filename:
        raise ValueError("Null byte injection detected")
        
    resolved_target = (BASE_STORAGE_DIR / user_filename).resolve()
    
    # Verify the target is within the base directory
    if not resolved_target.is_relative_to(BASE_STORAGE_DIR):
        raise PermissionError(f"Access denied: path traversal attempt for {user_filename}")
        
    if not resolved_target.is_file():
        raise FileNotFoundError(f"File not found: {user_filename}")
        
    return resolved_target.read_bytes()
`,
  },
  {
    title: 'Argon2id Password Hasher',
    category: 'Cryptographic Security',
    prompt: 'Write a secure password hashing and verification module using Argon2id or PBKDF2.',
    code: `import hashlib
import os
import hmac

def hash_password_securely(password: str) -> tuple[bytes, bytes]:
    """
    Generates a secure PBKDF2-HMAC-SHA256 password hash with 600,000 iterations.
    """
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password.encode('utf-8'),
        salt=salt,
        iterations=600_000,
        dklen=32
    )
    return salt, key

def verify_password_securely(password: str, salt: bytes, expected_key: bytes) -> bool:
    key = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password.encode('utf-8'),
        salt=salt,
        iterations=600_000,
        dklen=32
    )
    return hmac.compare_digest(key, expected_key)
`,
  },
];

export default function CodeWriterView({ onSelectCodeForAnalysis }) {
  const [selectedTemplate, setSelectedTemplate] = useState(PRESET_TEMPLATES[0]);
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(selectedTemplate.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <div className="view-title-group">
          <div className="view-title">
            <PenLine size={18} />
            <h2>Secure Code Writer & Synthesizer</h2>
          </div>
          <span className="view-subtitle">Generate hardened security implementations with built-in defenses against CWE vectors</span>
        </div>
      </div>

      <div className="writer-grid">
        {/* Templates Sidebar */}
        <div className="card-panel">
          <div className="panel-inner-head">
            <span className="section-label">Hardened Templates</span>
          </div>

          <div className="template-list">
            {PRESET_TEMPLATES.map((tmpl, idx) => (
              <button
                key={idx}
                type="button"
                className={`template-item-btn ${selectedTemplate === tmpl ? 'is-active' : ''}`}
                onClick={() => setSelectedTemplate(tmpl)}
              >
                <div className="template-item-head">
                  <span className="template-name">{tmpl.title}</span>
                  <span className="template-category">{tmpl.category}</span>
                </div>
                <p className="template-desc">{tmpl.prompt}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Code Preview & Actions */}
        <div className="card-panel">
          <div className="panel-inner-head">
            <div className="flex-between">
              <span className="section-label">{selectedTemplate.title}</span>
              <div className="fix-actions">
                <button type="button" className="btn btn-secondary" onClick={handleCopy}>
                  {copied ? <Check size={13} className="text-success" /> : <Copy size={13} />}
                  <span>{copied ? 'Copied' : 'Copy Code'}</span>
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => onSelectCodeForAnalysis(selectedTemplate.code)}
                >
                  <span>Test in Security Check</span>
                  <ArrowRight size={13} />
                </button>
              </div>
            </div>
          </div>

          <pre className="writer-code-box">
            <code>{selectedTemplate.code}</code>
          </pre>
        </div>
      </div>
    </div>
  );
}
