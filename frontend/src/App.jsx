import { useState, useRef, useEffect, useCallback } from 'react';
import Editor from '@monaco-editor/react';
import {
  Code,
  Shield,
  ShieldCheck,
  AlertTriangle,
} from 'lucide-react';

import BottomNav from './components/BottomNav';
import PageHeader from './components/PageHeader';
import FindingCard from './components/FindingCard';
import PageGuide from './components/PageGuide';
import Diagnostics from './components/Diagnostics';
import ConfirmDialog from './components/ConfirmDialog';
import DebuggerView from './components/views/DebuggerView';
import IngestCodeView from './components/views/IngestCodeView';
import CodeWriterView from './components/views/CodeWriterView';
import useSplitter from './utils/useSplitter';
import { SAMPLES } from './utils/samples';
import './App.css';

const API = 'http://127.0.0.1:8000';

const DEFAULT_CODE = `# ThreatLens Security Analyzer
# Paste or type Python code below, or pick a sample from the toolbar.

import os

def ping_host(user_supplied_host):
    # Vulnerable to command injection (CWE-78)
    cmd = "ping -c 1 " + user_supplied_host
    os.system(cmd)

if __name__ == "__main__":
    ping_host("127.0.0.1; cat /etc/passwd")
`;

export default function App() {
  const editorRef = useRef(null);
  const monacoRef = useRef(null);
  const decorRef = useRef([]);

  // Active navigation tab: 'security-check' | 'debugger' | 'ingest-code' | 'code-writer'
  const [activeTab, setActiveTab] = useState('security-check');

  // App state
  const [lineCount, setLineCount] = useState(13);
  const [backendUp, setBackendUp] = useState(null);
  const [panelState, setPanelState] = useState('idle'); // idle | loading | done | error
  const [findings, setFindings] = useState([]);
  const [visibleCount, setVisibleCount] = useState(0);
  const [error, setError] = useState('');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [lastScanDuration, setLastScanDuration] = useState(null);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [analysisElapsed, setAnalysisElapsed] = useState(0);
  const timerRef = useRef(null);

  // Dialogs & drawers
  const [diagnosticsOpen, setDiagnosticsOpen] = useState(false);
  const [confirmResetOpen, setConfirmResetOpen] = useState(false);
  const [pendingFixFinding, setPendingFixFinding] = useState(null);

  // Draggable splitter
  const { containerRef, onPointerDown, onKeyDown } = useSplitter({
    varName: '--split-w',
    storageKey: 'threatlens_split_w',
    initial: 580,
    min: 340,
    max: 1100,
  });

  // Periodic Backend Health Check
  const checkHealth = useCallback(() => {
    fetch(`${API}/health`, { signal: AbortSignal.timeout(4000) })
      .then((r) => setBackendUp(r.ok))
      .catch(() => setBackendUp(false));
  }, []);

  useEffect(() => {
    checkHealth();
    const id = setInterval(checkHealth, 15000);
    return () => {
      clearInterval(id);
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [checkHealth]);


  // Define custom Monaco Dark Grey Theme
  const defineMonacoThemes = (monaco) => {
    monaco.editor.defineTheme('threatlens-darkgrey', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'comment', foreground: '768390', fontStyle: 'italic' },
        { token: 'keyword', foreground: 'f47067', fontStyle: 'bold' },
        { token: 'string', foreground: '57ab5a' },
        { token: 'number', foreground: '6cb6ff' },
        { token: 'identifier', foreground: 'c9d1d9' },
        { token: 'delimiter', foreground: '8b949e' },
      ],
      colors: {
        'editor.background': '#0d0e11',
        'editor.foreground': '#c9d1d9',
        'editor.lineHighlightBackground': '#14161a',
        'editorLineNumber.foreground': '#3f444e',
        'editorLineNumber.activeForeground': '#c9d1d9',
        'editorCursor.foreground': '#58a6ff',
        'editor.selectionBackground': '#212c3d',
        'editorIndentGuide.background1': '#16181d',
        'editorIndentGuide.activeBackground1': '#2b3039',
      },
    });
  };

  // Monaco mount handler
  function handleEditorMount(editor, monaco) {
    editorRef.current = editor;
    monacoRef.current = monaco;

    defineMonacoThemes(monaco);
    monaco.editor.setTheme('threatlens-darkgrey');

    editor.onDidChangeModelContent(() => {
      setLineCount(editor.getModel().getLineCount());
    });
    setLineCount(editor.getModel().getLineCount());

    editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => {
      analyze();
    });
  }

  // Highlight finding lines in Monaco
  function highlightLines(fList) {
    const editor = editorRef.current;
    const monaco = monacoRef.current;
    if (!editor || !monaco) return;

    decorRef.current = editor.deltaDecorations(
      decorRef.current,
      fList.map((f) => ({
        range: new monaco.Range(f.line_start || 1, 1, f.line_end || f.line_start || 1, 1),
        options: {
          isWholeLine: true,
          className: 'hl-vuln-line',
          overviewRuler: {
            color: '#F85149',
            position: monaco.editor.OverviewRulerLane.Right,
          },
        },
      }))
    );
  }

  function clearHighlights() {
    const editor = editorRef.current;
    if (editor) {
      decorRef.current = editor.deltaDecorations(decorRef.current, []);
    }
  }

  // Jump to specific line on finding click
  function handleSelectFinding(finding) {
    setSelectedFinding(finding);
    const editor = editorRef.current;
    if (editor && finding.line_start) {
      editor.revealLineInCenter(finding.line_start);
      editor.setPosition({ lineNumber: finding.line_start, column: 1 });
      editor.focus();
    }
  }

  // Main Analyze action
  async function analyze() {
    const code = editorRef.current?.getValue()?.trim();
    if (!code) return;

    if (timerRef.current) clearInterval(timerRef.current);

    setPanelState('loading');
    setAnalysisProgress(5);
    setAnalysisElapsed(0);
    setVisibleCount(0);
    clearHighlights();
    setSelectedFinding(null);
    const startTime = performance.now();

    timerRef.current = setInterval(() => {
      const elapsed = Math.round(performance.now() - startTime);
      setAnalysisElapsed(elapsed);
      // Asymptotically approach ~93% while waiting
      const p = Math.min(93, Math.round(5 + 88 * (1 - Math.exp(-elapsed / 2200))));
      setAnalysisProgress(p);
    }, 40);

    try {
      const res = await fetch(`${API}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });

      if (timerRef.current) clearInterval(timerRef.current);
      const elapsed = Math.round(performance.now() - startTime);
      setLastScanDuration(elapsed);
      setAnalysisElapsed(elapsed);
      setAnalysisProgress(100);

      // Brief 200ms pause so the user visually catches the 100% full bar
      await new Promise((r) => setTimeout(r, 200));

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        const msg = typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail, null, 2);
        setError(`HTTP ${res.status}: ${msg}`);
        setPanelState('error');
        return;
      }

      const data = await res.json();
      const list = data.findings ?? [];
      setFindings(list);
      // Reveal first card immediately; subsequent cards unlock via onRevealNext
      setVisibleCount(list.length > 0 ? 1 : 0);
      setPanelState('done');
      highlightLines(list);
    } catch (e) {
      if (timerRef.current) clearInterval(timerRef.current);
      setAnalysisProgress(100);
      setError(e.message || 'Could not reach the backend. Ensure FastAPI (uvicorn) is running.');
      setPanelState('error');
    }
  }

  // Load code from outside (Ingest Code / Code Writer / Samples)
  function handleLoadCode(newCode) {
    if (editorRef.current) {
      editorRef.current.setValue(newCode);
    }
    setActiveTab('security-check');
    setPanelState('idle');
    setFindings([]);
    setSelectedFinding(null);
    clearHighlights();
  }

  // Reset code handler
  function handleConfirmReset() {
    if (editorRef.current) {
      editorRef.current.setValue('');
    }
    setPanelState('idle');
    setFindings([]);
    setSelectedFinding(null);
    clearHighlights();
    setConfirmResetOpen(false);
  }

  // Apply remediation fix to editor
  function handleApplyFix(finding) {
    setPendingFixFinding(finding);
  }

  function handleConfirmApplyFix() {
    if (!editorRef.current || !pendingFixFinding) return;
    const editor = editorRef.current;
    const model = editor.getModel();

    if (pendingFixFinding.line_start && pendingFixFinding.line_end) {
      const range = new monacoRef.current.Range(
        pendingFixFinding.line_start,
        1,
        pendingFixFinding.line_end,
        model.getLineMaxColumn(pendingFixFinding.line_end)
      );

      editor.executeEdits('threatlens-fix', [
        {
          range,
          text: pendingFixFinding.fix,
          forceMoveMarkers: true,
        },
      ]);
    } else {
      const fullRange = model.getFullModelRange();
      editor.executeEdits('threatlens-fix', [
        {
          range: fullRange,
          text: pendingFixFinding.fix,
          forceMoveMarkers: true,
        },
      ]);
    }

    setPendingFixFinding(null);
  }

  // Export report generator
  function handleExportReport(format) {
    if (findings.length === 0) return;
    const code = editorRef.current?.getValue() || '';

    let content = '';
    let filename = `threatlens-report-${Date.now()}`;

    if (format === 'json') {
      content = JSON.stringify({ timestamp: new Date().toISOString(), findings, code }, null, 2);
      filename += '.json';
    } else if (format === 'sarif') {
      const sarif = {
        version: '2.1.0',
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        runs: [
          {
            tool: {
              driver: {
                name: 'ThreatLens',
                version: '0.1.0',
                informationUri: 'https://github.com/ThreatLens',
                rules: findings.map((f) => ({
                  id: f.cwe_id,
                  name: f.vulnerability,
                  shortDescription: { text: f.description },
                  defaultConfiguration: { level: f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning' },
                })),
              },
            },
            results: findings.map((f) => ({
              ruleId: f.cwe_id,
              message: { text: `${f.vulnerability}: ${f.description}` },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'source.py' },
                    region: { startLine: f.line_start, endLine: f.line_end },
                  },
                },
              ],
            })),
          },
        ],
      };
      content = JSON.stringify(sarif, null, 2);
      filename += '.sarif';
    } else {
      content = `# ThreatLens Security Audit Report
Generated: ${new Date().toLocaleString()}
Vulnerabilities Found: ${findings.length}

---

${findings
  .map(
    (f, i) => `### ${i + 1}. [${f.cwe_id}] ${f.vulnerability} (${f.severity.toUpperCase()})
- **Location**: Line ${f.line_start} to ${f.line_end}
- **Description**: ${f.description}

**Remediation**:
\`\`\`python
${f.fix}
\`\`\`
`
  )
  .join('\n---\n')}
`;
      filename += '.md';
    }

    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  }

  const isLoading = panelState === 'loading';

  return (
    <div className="app-layout">
      {/* Main Content Region */}
      <div className="main-content">
        {/* Main Security Check Studio */}
        <div
          className="feature-view security-check-view"
          style={{
            display: activeTab === 'security-check' ? 'flex' : 'none',
            flexDirection: 'column',
            flex: 1,
            minHeight: 0,
            overflow: 'hidden',
          }}
        >
          {/* Top Masthead Header */}
          <PageHeader />

          {/* Split Workspace Layout */}
          <div className="workspace-container" ref={containerRef}>
              {/* Editor Column */}
              <div className="editor-column">
                <div className="editor-toolbar">
                  <div className="panel-tag">
                    <Code size={14} />
                    <span>Source Buffer</span>
                  </div>
                  <span className="lang-chip">Python 3.12</span>
                </div>

                <div className="editor-surface">
                  <Editor
                    height="100%"
                    defaultLanguage="python"
                    defaultValue={DEFAULT_CODE}
                    theme="threatlens-darkgrey"
                    onMount={handleEditorMount}
                    options={{
                      fontSize: 13.5,
                      fontFamily: "'IBM Plex Mono', 'JetBrains Mono', monospace",
                      fontLigatures: true,
                      minimap: { enabled: false },
                      scrollBeyondLastLine: false,
                      lineNumbers: 'on',
                      renderLineHighlight: 'line',
                      padding: { top: 14, bottom: 14 },
                      wordWrap: 'on',
                      smoothScrolling: true,
                      cursorBlinking: 'smooth',
                      tabSize: 4,
                    }}
                  />
                </div>

                <div className="editor-status-bar">
                  <span>{lineCount} lines • UTF-8</span>
                  <span>Press Ctrl+Enter to run analysis</span>
                </div>
              </div>

              {/* Draggable Divider Grip */}
              <div
                className="splitter-grip"
                onPointerDown={onPointerDown}
                onKeyDown={onKeyDown}
                tabIndex={0}
                role="separator"
                aria-label="Resize panels"
              />

              {/* Findings Column */}
              <div className="findings-column">
                <div className="findings-toolbar">
                  <div className="panel-tag">
                    <Shield size={14} />
                    <span>Audit Findings</span>
                  </div>

                  {panelState === 'done' && findings.length > 0 && (
                    <span className="findings-count-badge has-issues">
                      {findings.length} issue{findings.length > 1 ? 's' : ''} detected
                    </span>
                  )}
                  {panelState === 'done' && findings.length === 0 && (
                    <span className="findings-count-badge is-safe">No issues found</span>
                  )}
                </div>

                <div className="findings-scroll-area">
                  {panelState === 'idle' && (
                    <div className="empty-state-text">
                      READY FOR ANALYSIS
                    </div>
                  )}

                  {panelState === 'loading' && (
                    <div className="pixel-loading-container">
                      <div className="pixel-progress-frame">
                        {Array.from({ length: 16 }).map((_, i) => (
                          <div
                            key={i}
                            className={`pixel-segment ${
                              i < Math.round((analysisProgress / 100) * 16)
                                ? 'is-active'
                                : ''
                            }`}
                          />
                        ))}
                      </div>

                      <div className="pixel-loading-title">
                        ANALYZING{['', '.', '..', '...'][Math.floor((analysisElapsed / 320) % 4)]}
                      </div>

                      <div className="pixel-loading-meta">
                        <span>[ {(analysisElapsed / 1000).toFixed(1)}s ]</span>
                        <span className="pixel-dot-sep">•</span>
                        <span>{analysisProgress}%</span>
                      </div>
                    </div>
                  )}

                  {panelState === 'error' && (
                    <div className="error-banner">
                      <div className="error-title">
                        <AlertTriangle size={18} />
                        <span>Analysis Error</span>
                      </div>
                      <p className="error-msg">{error}</p>
                    </div>
                  )}

                  {panelState === 'done' && findings.length === 0 && (
                    <div className="retro-safe-state">
                      <div className="retro-safe-icon-wrap">
                        <ShieldCheck size={26} />
                      </div>
                      <div className="retro-safe-title">No issues found</div>
                      <p className="retro-safe-sub">
                        Clean source buffer • analyzed in {lastScanDuration}ms with 0 CWE detections
                      </p>
                    </div>
                  )}

                  {panelState === 'done' &&
                    findings.length > 0 &&
                    findings.slice(0, visibleCount).map((f, i) => (
                      <FindingCard
                        key={i}
                        finding={f}
                        index={i}
                        isActive={selectedFinding === f}
                        onSelectFinding={handleSelectFinding}
                        onApplyFix={handleApplyFix}
                        onRevealNext={
                          i === visibleCount - 1 && visibleCount < findings.length
                            ? () => setVisibleCount((c) => c + 1)
                            : undefined
                        }
                      />
                    ))}
                </div>
              </div>
            </div>
        </div>

        {/* Debugger View */}
        <div
          className="feature-view"
          style={{
            display: activeTab === 'debugger' ? 'flex' : 'none',
            flexDirection: 'column',
            flex: 1,
            minHeight: 0,
            overflow: 'hidden',
          }}
        >
          <DebuggerView />
        </div>

        {/* Ingest Code View */}
        <div
          className="feature-view"
          style={{
            display: activeTab === 'ingest-code' ? 'flex' : 'none',
            flexDirection: 'column',
            flex: 1,
            minHeight: 0,
            overflow: 'hidden',
          }}
        >
          <IngestCodeView onSelectCodeForAnalysis={handleLoadCode} />
        </div>

        {/* Code Writer View */}
        <div
          className="feature-view"
          style={{
            display: activeTab === 'code-writer' ? 'flex' : 'none',
            flexDirection: 'column',
            flex: 1,
            minHeight: 0,
            overflow: 'hidden',
          }}
        >
          <CodeWriterView onSelectCodeForAnalysis={handleLoadCode} />
        </div>
      </div>

      {/* Bottom Navigation Bar */}
      <BottomNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        backendUp={backendUp}
        onOpenDiagnostics={() => setDiagnosticsOpen(true)}
      />

      {/* Floating Page Guide popover */}
      <PageGuide />

      {/* Diagnostics / Telemetry Drawer */}
      <Diagnostics
        open={diagnosticsOpen}
        onClose={() => setDiagnosticsOpen(false)}
        backendUp={backendUp}
        lastScanDuration={lastScanDuration}
        lineCount={lineCount}
        findingsCount={findings.length}
      />

      {/* Reset Confirmation Dialog */}
      {confirmResetOpen && (
        <ConfirmDialog
          title="Reset Code Buffer?"
          body="This will clear the current code editor contents and reset active security findings."
          confirmLabel="Clear Editor"
          cancelLabel="Keep Code"
          danger={true}
          onConfirm={handleConfirmReset}
          onCancel={() => setConfirmResetOpen(false)}
        />
      )}

      {/* Apply Fix Confirmation Dialog */}
      {pendingFixFinding && (
        <ConfirmDialog
          title="Apply Remediation Patch?"
          body={`Apply suggested fix for ${pendingFixFinding.vulnerability} (${pendingFixFinding.cwe_id}) to lines ${pendingFixFinding.line_start}–${pendingFixFinding.line_end}?`}
          confirmLabel="Apply Patch"
          cancelLabel="Cancel"
          danger={false}
          onConfirm={handleConfirmApplyFix}
          onCancel={() => setPendingFixFinding(null)}
        />
      )}
    </div>
  );
}
