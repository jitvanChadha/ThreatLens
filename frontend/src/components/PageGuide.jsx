import { useEffect, useRef, useState } from 'react';
import { HelpCircle, X, Shield, AlertOctagon, Cpu, CheckCircle2 } from 'lucide-react';

export default function PageGuide({ label = 'ThreatLens Guide' }) {
  const [open, setOpen] = useState(false);
  const wrap = useRef(null);

  useEffect(() => {
    if (!open) return undefined;

    const onPointerDown = (e) => {
      if (!wrap.current?.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') setOpen(false);
    };

    document.addEventListener('pointerdown', onPointerDown, true);
    document.addEventListener('keydown', onKey, true);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown, true);
      document.removeEventListener('keydown', onKey, true);
    };
  }, [open]);

  return (
    <div ref={wrap} className="page-guide">
      {open && (
        <div className="page-guide-panel" role="dialog" aria-label={label}>
          <div className="pg-head">
            <div className="pg-title-row">
              <Shield size={16} className="pg-icon" />
              <span className="pg-title">ThreatLens Security Guide</span>
            </div>
            <button
              type="button"
              className="pg-close"
              onClick={() => setOpen(false)}
              aria-label="Close guide"
            >
              <X size={14} />
            </button>
          </div>

          <div className="pg-content">
            <p className="pg-lead">
              ThreatLens performs local static and semantic security analysis using an SLM (Small Language Model) running on Ollama.
            </p>

            <div className="pg-section">
              <div className="pg-section-title">
                <AlertOctagon size={13} /> Supported CWE Classes
              </div>
              <div className="pg-cwe-grid">
                <span className="cwe-pill">CWE-78 Command Injection</span>
                <span className="cwe-pill">CWE-89 SQL Injection</span>
                <span className="cwe-pill">CWE-22 Path Traversal</span>
                <span className="cwe-pill">CWE-502 Deserialization</span>
                <span className="cwe-pill">CWE-798 Hardcoded Secrets</span>
                <span className="cwe-pill">CWE-918 SSRF</span>
                <span className="cwe-pill">CWE-79 Cross-Site Scripting</span>
                <span className="cwe-pill">CWE-327 Broken Crypto</span>
                <span className="cwe-pill">CWE-330 Insecure Random</span>
                <span className="cwe-pill">CWE-20 Input Validation</span>
              </div>
            </div>

            <div className="pg-section">
              <div className="pg-section-title">
                <Cpu size={13} /> Inference Architecture
              </div>
              <p className="pg-text">
                Code is analyzed through a zero-leakage local pipeline. Prompts strictly constrain output to JSON schema with line numbers, descriptions, and verified remediation diffs.
              </p>
            </div>

            <div className="pg-section">
              <div className="pg-section-title">
                <CheckCircle2 size={13} /> Pro-Tips
              </div>
              <ul className="pg-list">
                <li>Click any finding card to immediately jump and highlight the code line in the editor.</li>
                <li>Use the <strong>&quot;Apply Fix&quot;</strong> button to automatically replace vulnerable logic.</li>
                <li>Switch code samples with the sample selector at the top.</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      <button
        type="button"
        className={`page-guide-btn ${open ? 'is-active' : ''}`}
        onClick={() => setOpen((v) => !v)}
        aria-label={label}
        aria-expanded={open}
        title="ThreatLens & CWE Guide"
      >
        <HelpCircle size={15} />
      </button>
    </div>
  );
}
