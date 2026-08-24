import { useState } from 'react';
import { Bug, Play, Terminal, ShieldAlert, CheckCircle2 } from 'lucide-react';

export default function DebuggerView() {
  const [testInput, setTestInput] = useState('127.0.0.1; cat /etc/passwd');
  const [debugState, setDebugState] = useState('idle');
  const [executionTrace, setExecutionTrace] = useState(null);

  const runSimulation = () => {
    setDebugState('running');
    setTimeout(() => {
      setDebugState('done');
      setExecutionTrace({
        entryPoint: 'ping_host(user_supplied_host)',
        taintedVariables: [
          { name: 'user_supplied_host', value: testInput, source: 'User Input / Untrusted', tainted: true },
          { name: 'cmd', value: `ping -c 1 ${testInput}`, source: 'String Concatenation', tainted: true },
        ],
        sink: 'os.system(cmd)',
        isExploitable: testInput.includes(';') || testInput.includes('|') || testInput.includes('&'),
        steps: [
          { step: 1, action: 'Function entry: ping_host() called with untrusted string', status: 'info' },
          { step: 2, action: 'Variable tainted: "cmd" receives unsanitized input without validation', status: 'warning' },
          { step: 3, action: 'Dangerous sink reached: os.system() spawned shell with command chaining separator ";"', status: 'danger' },
          { step: 4, action: 'Arbitrary execution confirmed: "cat /etc/passwd" injected into subprocess', status: 'critical' },
        ],
      });
    }, 600);
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <div className="view-title-group">
          <div className="view-title">
            <Bug size={18} />
            <h2>Security Debugger & Trace Simulator</h2>
          </div>
          <span className="view-subtitle">Interactive taint analysis and payload flow simulation</span>
        </div>
      </div>

      <div className="debugger-grid">
        {/* Left Debug Panel */}
        <div className="card-panel">
          <div className="panel-inner-head">
            <span className="section-label">Payload Injection Testbed</span>
          </div>

          <div className="input-group">
            <label className="input-label">Simulated Input Argument (User Payload)</label>
            <input
              type="text"
              className="text-input"
              value={testInput}
              onChange={(e) => setTestInput(e.target.value)}
              placeholder="e.g. 127.0.0.1; id"
            />
          </div>

          <div className="quick-payloads">
            <span className="text-muted">Preset Payloads:</span>
            <button
              type="button"
              className="chip-btn"
              onClick={() => setTestInput("127.0.0.1; cat /etc/passwd")}
            >
              Command Chain (;)
            </button>
            <button
              type="button"
              className="chip-btn"
              onClick={() => setTestInput("' OR '1'='1")}
            >
              SQL Bypass (&#39; OR 1=1)
            </button>
            <button
              type="button"
              className="chip-btn"
              onClick={() => setTestInput("../../../../etc/shadow")}
            >
              Path Traversal (../)
            </button>
          </div>

          <button
            type="button"
            className="btn btn-primary"
            onClick={runSimulation}
            disabled={debugState === 'running'}
          >
            <Play size={13} className="fill-current" />
            <span>{debugState === 'running' ? 'Simulating…' : 'Execute Taint Trace'}</span>
          </button>
        </div>

        {/* Right Trace Results */}
        <div className="card-panel">
          <div className="panel-inner-head">
            <span className="section-label">Execution Trace & Sink Analysis</span>
          </div>

          {debugState === 'idle' && (
            <div className="empty-box">
              <Terminal size={32} />
              <p>Configure a payload on the left and click <strong>Execute Taint Trace</strong> to trace variable propagation to dangerous sinks.</p>
            </div>
          )}

          {debugState === 'running' && (
            <div className="empty-box">
              <div className="btn-spinner" style={{ width: 24, height: 24, borderColor: 'var(--rule-2)', borderTopColor: 'var(--ink)' }} />
              <p>Evaluating AST flow and taint propagation…</p>
            </div>
          )}

          {debugState === 'done' && executionTrace && (
            <div className="trace-results">
              <div className={`trace-verdict ${executionTrace.isExploitable ? 'is-exploitable' : 'is-safe'}`}>
                {executionTrace.isExploitable ? (
                  <>
                    <ShieldAlert size={18} />
                    <span>Sink Exploitation Confirmed: Critical Taint Reached Execution Vector</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 size={18} />
                    <span>Payload Sanitized: No Execution Anomaly Detected</span>
                  </>
                )}
              </div>

              <div className="trace-flow-list">
                {executionTrace.steps.map((st) => (
                  <div key={st.step} className={`trace-step-item status-${st.status}`}>
                    <span className="step-num">Step {st.step}</span>
                    <span className="step-desc">{st.action}</span>
                  </div>
                ))}
              </div>

              <div className="taint-summary">
                <div className="section-label">Monitored Variables</div>
                <div className="vars-table">
                  {executionTrace.taintedVariables.map((v, i) => (
                    <div key={i} className="var-row">
                      <code className="var-name">{v.name}</code>
                      <code className="var-val">{v.value}</code>
                      <span className="var-source">{v.source}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
