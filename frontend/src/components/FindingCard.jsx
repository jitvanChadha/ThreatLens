import { ArrowUpRight, ShieldAlert } from 'lucide-react';

function lineLabel(f) {
  if (!f.line_start && !f.line_end) return null;
  return f.line_start === f.line_end
    ? `Line ${f.line_start}`
    : `Lines ${f.line_start}–${f.line_end}`;
}

export default function FindingCard({
  finding,
  index,
  isActive,
  onSelectFinding,
}) {
  const lineTxt = lineLabel(finding);

  return (
    <div
      className={`finding-card ${isActive ? 'is-active' : ''}`}
      style={{ animationDelay: `${index * 0.05}s` }}
      onClick={() => onSelectFinding?.(finding)}
    >
      {lineTxt && (
        <div className="card-head">
          <div className="card-head-left" />
          <button
            type="button"
            className="line-pill-btn"
            onClick={(e) => {
              e.stopPropagation();
              onSelectFinding?.(finding);
            }}
            title="Click to jump to line in editor"
          >
            <span>{lineTxt}</span>
            <ArrowUpRight size={11} />
          </button>
        </div>
      )}

      <div className="card-body">
        <div className="vuln-name">
          <ShieldAlert size={15} className="vuln-icon" />
          <span>{finding.vulnerability}</span>
        </div>

        <div className="section-block">
          <p className="desc-text">{finding.description}</p>
        </div>

        {finding.fix && (
          <div className="fix-block">
            <div className="fix-header">
              <span className="section-label">Remediation Strategy</span>
            </div>
            <pre className="fix-code-box">
              <code>{finding.fix}</code>
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
