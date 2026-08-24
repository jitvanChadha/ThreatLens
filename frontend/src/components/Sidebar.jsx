import { ShieldCheck, Bug, FolderGit2, PenLine, Activity } from 'lucide-react';

const NAV_ITEMS = [
  {
    id: 'security-check',
    label: 'Security Check',
    icon: ShieldCheck,
    description: 'Static & Semantic CWE Security Analysis',
  },
  {
    id: 'debugger',
    label: 'Debugger',
    icon: Bug,
    description: 'Vulnerability Execution Tracer & Taint Analysis',
  },
  {
    id: 'ingest-code',
    label: 'Ingest Code',
    icon: FolderGit2,
    description: 'Multi-File Workspace & Repository Ingestion',
  },
  {
    id: 'code-writer',
    label: 'Code Writer',
    icon: PenLine,
    description: 'AI Secure Code Synthesizer & Hardener',
  },
];

export default function Sidebar({
  activeTab,
  onSelectTab,
  backendUp,
  onOpenDiagnostics,
}) {
  return (
    <aside className="sidebar">
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="brand-logo-container">
          <h1>
            <div className="brand-logo-icon">
              <ShieldCheck size={20} />
            </div>
            ThreatLens
          </h1>
        </div>
        <div className="brand-subtitle">Security Intelligence</div>
      </div>

      {/* Nav links */}
      <nav className="sidebar-nav">
        {NAV_ITEMS.map(({ id, label, icon: Icon }) => {
          const isActive = activeTab === id;
          return (
            <button
              key={id}
              type="button"
              className={`nav-link ${isActive ? 'active' : ''}`}
              onClick={() => onSelectTab(id)}
            >
              <Icon size={16} />
              <span>{label}</span>
            </button>
          );
        })}
      </nav>

      {/* Sidebar Footer */}
      <div className="sidebar-footer">
        {/* Status Indicator */}
        <div
          className="status-indicator"
          onClick={onOpenDiagnostics}
          title="Click to view telemetry"
          role="button"
          tabIndex={0}
        >
          <div
            className={`status-dot ${
              backendUp === true ? 'is-online' : backendUp === false ? 'is-offline' : 'is-connecting'
            }`}
          />
          <span>{backendUp === true ? 'System Online' : backendUp === false ? 'System Offline' : 'Connecting…'}</span>
        </div>

        {/* Sidebar quick tools */}
        <div className="sidebar-tools">
          <button
            type="button"
            className="sidebar-tool"
            onClick={onOpenDiagnostics}
            title="System Telemetry & Specs"
          >
            <Activity size={14} />
            <span>Diagnostics</span>
          </button>

          <div className="sidebar-version-tag">v0.1.0</div>
        </div>
      </div>
    </aside>
  );
}
