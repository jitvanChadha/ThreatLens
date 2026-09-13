import { useState, useRef, useCallback } from 'react';
import {
  FolderOpen,
  FileCode,
  Archive,
  Upload,
  Shield,
  ShieldCheck,
  AlertTriangle,
  Loader2,
  ChevronDown,
  ChevronUp,
  ArrowRight,
  Trash2,
  X,
  FolderGit2,
} from 'lucide-react';

const API = 'http://127.0.0.1:8000';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITY_CLASS = {
  critical: 'sev-critical',
  high: 'sev-high',
  medium: 'sev-medium',
  low: 'sev-low',
};

/* ─── tiny helpers ────────────────────────────────────────────── */
function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function langColor(lang) {
  const map = {
    python: '#3b82f6',
    javascript: '#f59e0b',
    typescript: '#06b6d4',
    go: '#10b981',
    java: '#f97316',
    rust: '#ef4444',
    csharp: '#8b5cf6',
    shell: '#6b7280',
    yaml: '#84cc16',
    json: '#ec4899',
    toml: '#f59e0b',
  };
  return map[lang] || '#6b7280';
}

/* ─── FileResultCard ──────────────────────────────────────────── */
function FileResultCard({ result, onSendToEditor }) {
  const [expanded, setExpanded] = useState(result.findings.length > 0);
  const hasError = Boolean(result.error);
  const count = result.findings.length;

  return (
    <div className={`file-result-card ${hasError ? 'file-result-error' : ''}`}>
      {/* Card Header */}
      <div
        className="file-result-header"
        onClick={() => !hasError && setExpanded((v) => !v)}
        style={{ cursor: hasError ? 'default' : 'pointer' }}
      >
        <div className="file-result-left">
          <FileCode size={15} />
          <span className="file-result-name">{result.filename}</span>
          {result.language && (
            <span
              className="lang-tag"
              style={{ '--lang-color': langColor(result.language) }}
            >
              {result.language}
            </span>
          )}
        </div>

        <div className="file-result-right">
          {hasError ? (
            <span className="file-result-skipped">skipped</span>
          ) : count === 0 ? (
            <span className="file-result-clean">
              <ShieldCheck size={12} /> Clean
            </span>
          ) : (
            <span className={`findings-count-badge has-issues`}>
              {count} issue{count !== 1 ? 's' : ''}
            </span>
          )}

          {!hasError && (
            <button
              className="btn btn-ghost btn-icon-only"
              onClick={(e) => {
                e.stopPropagation();
                onSendToEditor(result.filename, result.findings);
              }}
              title="Send to Security Check"
            >
              <ArrowRight size={13} />
            </button>
          )}

          {!hasError && (
            <span className="expand-icon">
              {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </span>
          )}
        </div>
      </div>

      {/* Error message */}
      {hasError && (
        <div className="file-result-error-body">{result.error}</div>
      )}

      {/* Findings list */}
      {!hasError && expanded && count > 0 && (
        <div className="file-result-findings">
          {result.findings
            .slice()
            .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9))
            .map((f, i) => (
              <div key={i} className="ingest-finding-row">
                <span className={`sev-dot ${SEVERITY_CLASS[f.severity] || ''}`} />
                <span className="ingest-finding-cwe">{f.cwe_id}</span>
                <span className="ingest-finding-vuln">{f.vulnerability}</span>
                <span className="ingest-finding-loc">
                  L{f.line_start}–{f.line_end}
                </span>
              </div>
            ))}
        </div>
      )}
    </div>
  );
}

/* ─── DropZone ────────────────────────────────────────────────── */
function DropZone({ onDrop, accept, label, sub, icon: Icon }) {
  const [drag, setDrag] = useState(false);

  return (
    <div
      className={`drop-panel ${drag ? 'is-drag-over' : ''}`}
      onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
      onDragLeave={() => setDrag(false)}
      onDrop={(e) => { e.preventDefault(); setDrag(false); onDrop(e.dataTransfer.files); }}
    >
      <div className="drop-icon"><Icon size={26} /></div>
      <div className="drop-title">{label}</div>
      <p className="drop-sub">{sub}</p>
    </div>
  );
}

/* ─── Main View ───────────────────────────────────────────────── */
export default function IngestCodeView({ onSelectCodeForAnalysis }) {
  const fileInputRef   = useRef(null);   // individual files
  const folderInputRef = useRef(null);   // folder picker (webkitdirectory)
  const zipInputRef    = useRef(null);   // ZIP upload

  const [scanState, setScanState] = useState('idle'); // idle | scanning | done | error
  const [scanError, setScanError] = useState('');
  const [response, setResponse] = useState(null);     // IngestResponse from API

  /* ── post to /ingest/files ── */
  const submitFiles = useCallback(async (fileList) => {
    if (!fileList || fileList.length === 0) return;
    setScanState('scanning');
    setScanError('');
    setResponse(null);

    const fd = new FormData();
    Array.from(fileList).forEach((f) => fd.append('files', f, f.webkitRelativePath || f.name));

    try {
      const res = await fetch(`${API}/ingest/files`, { method: 'POST', body: fd });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail));
      }
      const data = await res.json();
      setResponse(data);
      setScanState('done');
    } catch (e) {
      setScanError(e.message || 'Could not reach the backend.');
      setScanState('error');
    }
  }, []);

  /* ── post to /ingest/folder (ZIP) ── */
  const submitZip = useCallback(async (fileList) => {
    const file = fileList[0];
    if (!file) return;
    setScanState('scanning');
    setScanError('');
    setResponse(null);

    const fd = new FormData();
    fd.append('folder', file);

    try {
      const res = await fetch(`${API}/ingest/folder`, { method: 'POST', body: fd });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail));
      }
      const data = await res.json();
      setResponse(data);
      setScanState('done');
    } catch (e) {
      setScanError(e.message || 'Could not reach the backend.');
      setScanState('error');
    }
  }, []);

  const reset = () => {
    setScanState('idle');
    setScanError('');
    setResponse(null);
  };

  /* ── send to Security Check tab: load first file's content via FileReader ── */
  const handleSendToEditor = (filename) => {
    // We can't re-read server-side content, so just notify the user
    // In a real flow the user would re-open the file. For now, no-op.
    alert(`Open "${filename}" in your editor and paste it into Security Check.`);
  };

  const totalIssues = response?.files.reduce((s, f) => s + f.findings.length, 0) ?? 0;

  return (
    <div className="view-container">
      {/* ── Header ── */}
      <div className="view-header">
        <div className="view-title-group">
          <div className="view-title">
            <FolderGit2 size={18} />
            <h2>Batch File Ingestion</h2>
          </div>
          <span className="view-subtitle">
            Scan individual files, an entire project folder, or a ZIP archive — all via the local LLM
          </span>
        </div>
        {scanState !== 'idle' && (
          <button className="btn btn-ghost" onClick={reset}>
            <X size={14} /> New Scan
          </button>
        )}
      </div>

      {/* ── Upload area (shown until a scan is done) ── */}
      {scanState === 'idle' && (
        <div className="ingest-upload-grid">

          {/* Option 1: Individual files */}
          <div className="ingest-upload-card" onClick={() => fileInputRef.current?.click()}>
            <div className="ingest-upload-icon"><FileCode size={28} /></div>
            <div className="ingest-upload-label">Pick Files</div>
            <div className="ingest-upload-sub">
              Select one or more source files<br />
              <code>.py .js .ts .go .java .rs …</code>
            </div>
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".py,.js,.ts,.jsx,.tsx,.go,.java,.rb,.php,.c,.cpp,.cs,.rs,.sh,.yaml,.yml,.toml,.json"
              style={{ display: 'none' }}
              onChange={(e) => e.target.files && submitFiles(e.target.files)}
            />
          </div>

          {/* Option 2: Whole folder */}
          <div className="ingest-upload-card ingest-upload-card--highlight" onClick={() => folderInputRef.current?.click()}>
            <div className="ingest-upload-icon"><FolderOpen size={28} /></div>
            <div className="ingest-upload-label">Pick Folder</div>
            <div className="ingest-upload-sub">
              Select an entire project directory<br />
              All supported source files are scanned
            </div>
            <input
              ref={folderInputRef}
              type="file"
              // These two attributes let the browser expose a folder picker
              // eslint-disable-next-line react/no-unknown-property
              webkitdirectory=""
              // eslint-disable-next-line react/no-unknown-property
              directory=""
              multiple
              style={{ display: 'none' }}
              onChange={(e) => e.target.files && submitFiles(e.target.files)}
            />
          </div>

          {/* Option 3: ZIP upload */}
          <div className="ingest-upload-card" onClick={() => zipInputRef.current?.click()}>
            <div className="ingest-upload-icon"><Archive size={28} /></div>
            <div className="ingest-upload-label">Upload ZIP</div>
            <div className="ingest-upload-sub">
              Compress your project and upload<br />
              a <code>.zip</code> archive
            </div>
            <input
              ref={zipInputRef}
              type="file"
              accept=".zip"
              style={{ display: 'none' }}
              onChange={(e) => e.target.files && submitZip(e.target.files)}
            />
          </div>
        </div>
      )}

      {/* Drag-and-drop zone (idle state only) */}
      {scanState === 'idle' && (
        <DropZone
          icon={Upload}
          label="Or drop files / a ZIP here"
          sub="Drag source files from your file manager directly onto this zone"
          accept="*"
          onDrop={(files) => {
            const first = files[0];
            if (first?.name.endsWith('.zip')) submitZip(files);
            else submitFiles(files);
          }}
        />
      )}

      {/* ── Scanning state ── */}
      {scanState === 'scanning' && (
        <div className="loading-state">
          <div className="scanning-orb" />
          <div className="loading-title">Scanning files…</div>
          <span className="loading-sub">
            Running regex + local LLM analysis on each file sequentially
          </span>
        </div>
      )}

      {/* ── Error state ── */}
      {scanState === 'error' && (
        <div className="error-banner">
          <div className="error-title">
            <AlertTriangle size={18} />
            <span>Scan Failed</span>
          </div>
          <p className="error-msg">{scanError}</p>
          <button className="btn btn-secondary" onClick={reset}>Try Again</button>
        </div>
      )}

      {/* ── Results ── */}
      {scanState === 'done' && response && (
        <>
          {/* Summary bar */}
          <div className="ingest-summary-bar">
            <div className="ingest-summary-stat">
              <span className="ingest-summary-num">{response.total_files}</span>
              <span className="ingest-summary-lbl">files received</span>
            </div>
            <div className="ingest-summary-stat">
              <span className="ingest-summary-num">{response.analysed}</span>
              <span className="ingest-summary-lbl">analysed</span>
            </div>
            <div className="ingest-summary-stat">
              <span className="ingest-summary-num">{response.skipped}</span>
              <span className="ingest-summary-lbl">skipped</span>
            </div>
            <div className="ingest-summary-stat">
              <span
                className="ingest-summary-num"
                style={{ color: totalIssues > 0 ? 'var(--sev-high)' : 'var(--clr-accent)' }}
              >
                {totalIssues}
              </span>
              <span className="ingest-summary-lbl">total issues</span>
            </div>

            {totalIssues === 0 && (
              <div className="ingest-all-clean">
                <ShieldCheck size={16} />
                All scanned files are clean
              </div>
            )}
          </div>

          {/* Per-file results */}
          <div className="card-panel">
            <div className="panel-inner-head">
              <Shield size={14} />
              <span className="section-label">File Scan Results</span>
            </div>
            <div className="file-result-list">
              {response.files.map((r, i) => (
                <FileResultCard
                  key={i}
                  result={r}
                  onSendToEditor={handleSendToEditor}
                />
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
