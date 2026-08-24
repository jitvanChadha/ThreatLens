import { useEffect } from 'react';
import { Activity, Server, ShieldCheck, Clock, X, Database } from 'lucide-react';

export default function Diagnostics({
  open,
  onClose,
  backendUp,
  lastScanDuration,
  lineCount,
  findingsCount,
  modelName = 'qwen2.5-coder:7b',
}) {
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => {
      if (e.key === 'Escape') onClose?.();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="diag-overlay" onClick={onClose}>
      <div className="diag-drawer" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="System Diagnostics">
        <div className="diag-head">
          <div className="diag-head-left">
            <Activity size={18} className="diag-icon" />
            <div>
              <h3>System Telemetry & Engine</h3>
              <span className="diag-sub">ThreatLens Local Inference Diagnostics</span>
            </div>
          </div>
          <button type="button" className="btn-icon" onClick={onClose} aria-label="Close telemetry">
            <X size={16} />
          </button>
        </div>

        <div className="diag-body">
          <div className="diag-section">
            <div className="diag-section-header">
              <Server size={14} /> Backend & Host Status
            </div>
            <dl className="diag-spec">
              <div className="spec-row">
                <dt>Backend API</dt>
                <dd>
                  <span className={`status-pill ${backendUp ? 'is-online' : 'is-offline'}`}>
                    {backendUp ? 'Online (FastAPI :8000)' : 'Offline / Unreachable'}
                  </span>
                </dd>
              </div>
              <div className="spec-row">
                <dt>Analysis Engine</dt>
                <dd className="mono-val">Ollama Local Daemon</dd>
              </div>
              <div className="spec-row">
                <dt>Configured SLM</dt>
                <dd className="mono-val">{modelName}</dd>
              </div>
            </dl>
          </div>

          <div className="diag-section">
            <div className="diag-section-header">
              <Clock size={14} /> Performance & Telemetry
            </div>
            <dl className="diag-spec">
              <div className="spec-row">
                <dt>Last Scan Latency</dt>
                <dd className="mono-val">{lastScanDuration ? `${(lastScanDuration / 1000).toFixed(2)}s` : '—'}</dd>
              </div>
              <div className="spec-row">
                <dt>Code Buffer Size</dt>
                <dd className="mono-val">{lineCount} lines</dd>
              </div>
              <div className="spec-row">
                <dt>Detected Vulnerabilities</dt>
                <dd className="mono-val">{findingsCount} issues</dd>
              </div>
            </dl>
          </div>

          <div className="diag-section">
            <div className="diag-section-header">
              <ShieldCheck size={14} /> Security & Privacy Posture
            </div>
            <div className="diag-privacy-card">
              <p>
                <strong>Zero Data Egress:</strong> Code analyzed by ThreatLens is never transmitted over external networks or third-party APIs. All inference runs strictly inside your local Ollama runtime.
              </p>
            </div>
          </div>

          <div className="diag-section">
            <div className="diag-section-header">
              <Database size={14} /> Prompt & Schema Integrity
            </div>
            <p className="diag-info-text">
              Pydantic model-validated JSON array extraction with strict bounding constraints on start/end lines and verified remediation strings.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
