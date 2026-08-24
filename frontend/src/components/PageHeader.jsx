import { useState, useRef, useEffect } from 'react';
import {
  Play,
  RotateCcw,
  Code2,
  ChevronDown,
} from 'lucide-react';
import { SAMPLES } from '../utils/samples';

export default function PageHeader({
  isLoading,
  lineCount,
  findingsCount,
  onAnalyze,
  onResetCode,
  onSelectSample,
}) {
  const [sampleMenuOpen, setSampleMenuOpen] = useState(false);
  const sampleMenuRef = useRef(null);

  useEffect(() => {
    const onDocClick = (e) => {
      if (sampleMenuRef.current && !sampleMenuRef.current.contains(e.target)) {
        setSampleMenuOpen(false);
      }
    };
    document.addEventListener('pointerdown', onDocClick);
    return () => document.removeEventListener('pointerdown', onDocClick);
  }, []);

  return (
    <header className="page-header">
      <div className="header-left">
        <div className="header-folio">
          <span className="folio-item">
            <b>{lineCount}</b> {lineCount === 1 ? 'line' : 'lines'}
          </span>
          <span className="folio-sep">/</span>
          <span className={`folio-item ${findingsCount > 0 ? 'has-findings' : ''}`}>
            <b>{findingsCount}</b> {findingsCount === 1 ? 'issue' : 'issues'}
          </span>
        </div>
      </div>

      <div className="header-right">
        {/* Sample snippet picker */}
        <div className="menu-container" ref={sampleMenuRef}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setSampleMenuOpen((v) => !v)}
            aria-expanded={sampleMenuOpen}
          >
            <Code2 size={13} />
            <span>Samples</span>
            <ChevronDown size={12} />
          </button>

          {sampleMenuOpen && (
            <div className="dropdown-menu">
              <div className="dropdown-label">Vulnerability Test Cases</div>
              {SAMPLES.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  className="dropdown-item"
                  onClick={() => {
                    onSelectSample(s);
                    setSampleMenuOpen(false);
                  }}
                >
                  <div className="sample-item-info">
                    <span className="sample-item-title">{s.title}</span>
                    <span className="sample-item-desc">{s.description}</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Reset code */}
        <button
          type="button"
          className="btn btn-secondary btn-icon-only"
          onClick={onResetCode}
          title="Reset / Clear Code"
          disabled={isLoading}
        >
          <RotateCcw size={14} />
        </button>

        {/* Primary analyze action */}
        <button
          type="button"
          className="btn btn-primary analyze-action-btn"
          onClick={onAnalyze}
          disabled={isLoading}
        >
          {isLoading ? (
            <>
              <div className="btn-spinner" />
              <span>Analyzing…</span>
            </>
          ) : (
            <>
              <Play size={13} className="fill-current" />
              <span>Analyze</span>
              <span className="kbd-hint">Ctrl+↵</span>
            </>
          )}
        </button>
      </div>
    </header>
  );
}
