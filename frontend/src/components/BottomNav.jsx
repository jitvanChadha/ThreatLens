import { ShieldCheck, Bug, FolderGit2, PenLine, Activity } from 'lucide-react';

const NAV_ITEMS = [
  { id: 'security-check', label: 'Security Check', icon: ShieldCheck },
  { id: 'debugger',       label: 'Debugger',        icon: Bug },
  { id: 'ingest-code',   label: 'Ingest Code',      icon: FolderGit2 },
  { id: 'code-writer',   label: 'Code Writer',       icon: PenLine },
];

export default function BottomNav({
  activeTab,
  onSelectTab,
  backendUp,
  onOpenDiagnostics,
}) {
  return (
    /* Wrapper strip — sits below panels in normal flow */
    <div className="bottom-nav-strip">
      <nav className="bottom-nav" aria-label="Main navigation">
        {/* Nav icons — centered */}
        <div className="bottom-nav-items">
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => {
            const isActive = activeTab === id;
            return (
              <button
                key={id}
                type="button"
                id={`nav-${id}`}
                className={`bottom-nav-btn${isActive ? ' is-active' : ''}`}
                onClick={() => onSelectTab(id)}
                aria-label={label}
                aria-current={isActive ? 'page' : undefined}
              >
                <Icon size={18} />
                <span className="bottom-nav-tooltip">{label}</span>
              </button>
            );
          })}
        </div>

        {/* Status / Diagnostics */}
        <button
          type="button"
          id="nav-diagnostics"
          className="bottom-nav-status-btn"
          onClick={onOpenDiagnostics}
          aria-label="System diagnostics"
        >
          <div
            className={`status-dot${
              backendUp === true ? ' is-online' : backendUp === false ? ' is-offline' : ' is-connecting'
            }`}
          />
          <Activity size={15} />
          <span className="bottom-nav-tooltip">
            {backendUp === true ? 'Online' : backendUp === false ? 'Offline' : 'Connecting…'}
          </span>
        </button>
      </nav>
    </div>
  );
}
