import { useState, useRef } from 'react';
import { FolderGit2, Upload, FileCode, ArrowRight, Trash2 } from 'lucide-react';
import { SAMPLES } from '../../utils/samples';

export default function IngestCodeView({ onSelectCodeForAnalysis }) {
  const [ingestedFiles, setIngestedFiles] = useState([
    {
      name: 'server_handler.py',
      size: '1.2 KB',
      lines: 24,
      code: SAMPLES[0].code,
      cwe: 'CWE-78',
    },
    {
      name: 'database_query.py',
      size: '890 B',
      lines: 16,
      code: SAMPLES[1].code,
      cwe: 'CWE-89',
    },
    {
      name: 'session_auth.py',
      size: '1.5 KB',
      lines: 32,
      code: SAMPLES[3].code,
      cwe: 'CWE-502',
    },
  ]);

  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef(null);

  const handleFileUpload = (files) => {
    Array.from(files).forEach((file) => {
      if (file.name.endsWith('.py') || file.name.endsWith('.txt') || file.name.endsWith('.json')) {
        const reader = new FileReader();
        reader.onload = (e) => {
          const content = e.target.result;
          const lines = content.split('\n').length;
          setIngestedFiles((prev) => [
            {
              name: file.name,
              size: `${(file.size / 1024).toFixed(1)} KB`,
              lines,
              code: content,
              cwe: 'Custom',
            },
            ...prev,
          ]);
        };
        reader.readAsText(file);
      }
    });
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files?.length) {
      handleFileUpload(e.dataTransfer.files);
    }
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <div className="view-title-group">
          <div className="view-title">
            <FolderGit2 size={18} />
            <h2>Code Ingestion & Workspace</h2>
          </div>
          <span className="view-subtitle">Import multi-file Python modules, scripts, or local repositories</span>
        </div>
      </div>

      {/* Drop Zone */}
      <div
        className={`drop-panel ${isDragging ? 'is-drag-over' : ''}`}
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
      >
        <div className="drop-icon">
          <Upload size={28} />
        </div>
        <div className="drop-title">Drop Python files here to ingest</div>
        <p className="drop-sub">
          Drag and drop <code>.py</code> files or click below to browse local filesystem
        </p>
        <input
          type="file"
          ref={fileInputRef}
          multiple
          accept=".py,.txt,.json"
          style={{ display: 'none' }}
          onChange={(e) => e.target.files && handleFileUpload(e.target.files)}
        />
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => fileInputRef.current?.click()}
        >
          Browse Files
        </button>
      </div>

      {/* Ingested File List */}
      <div className="card-panel">
        <div className="panel-inner-head">
          <span className="section-label">Workspace Files ({ingestedFiles.length})</span>
        </div>

        <div className="file-list">
          {ingestedFiles.map((file, idx) => (
            <div key={idx} className="file-row">
              <div className="file-info-left">
                <FileCode size={16} className="file-icon" />
                <div>
                  <div className="file-name">{file.name}</div>
                  <div className="file-meta">
                    {file.lines} lines • {file.size}
                  </div>
                </div>
              </div>

              <div className="file-actions">
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => onSelectCodeForAnalysis(file.code)}
                >
                  <span>Analyze in Security Check</span>
                  <ArrowRight size={13} />
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-icon-only"
                  onClick={() => setIngestedFiles((prev) => prev.filter((_, i) => i !== idx))}
                  title="Remove file"
                >
                  <Trash2 size={13} />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
