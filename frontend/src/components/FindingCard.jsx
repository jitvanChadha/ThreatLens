import { useState, useEffect } from 'react';
import { useTypewriter } from '../utils/useTypewriter';

function lineLabel(f) {
  if (!f.line_start && !f.line_end) return null;
  return f.line_start === f.line_end
    ? `L${f.line_start}`
    : `L${f.line_start}–${f.line_end}`;
}

// The full "line" string that gets typed out character-by-character
function buildLineString(finding, index) {
  const num  = String(index + 1).padStart(2, '0');
  const vuln = finding.vulnerability || '';
  const line = lineLabel(finding) ? `  ${lineLabel(finding)}` : '';
  return `[${num}]  ${vuln}${line}`;
}

export default function FindingCard({
  finding,
  index,
  isActive,
  onSelectFinding,
  onApplyFix,
  onRevealNext,
}) {
  const [expanded, setExpanded] = useState(true);

  // 1. Title line typing
  const lineString = buildLineString(finding, index);
  const { displayed: displayedTitle, done: titleDone } = useTypewriter(lineString, 14, 0, true);

  // 2. Description typing - only starts after title is done
  const hasDesc = Boolean(finding.description);
  const { displayed: displayedDesc, done: descDone } = useTypewriter(
    finding.description || '',
    8,
    60,
    titleDone && hasDesc
  );
  const isDescEffectivelyDone = !hasDesc || descDone;

  // 3. Fix typing - only starts after description is done
  const hasFix = Boolean(finding.fix);
  const { displayed: displayedFix, done: fixDone } = useTypewriter(
    finding.fix || '',
    6,
    60,
    titleDone && isDescEffectivelyDone && hasFix
  );
  const isFixEffectivelyDone = !hasFix || fixDone;

  // 4. Trigger next finding ONLY when title, entire desc, and entire fix are done
  const isCardFullyDone = titleDone && isDescEffectivelyDone && isFixEffectivelyDone;

  useEffect(() => {
    if (isCardFullyDone && onRevealNext) {
      const t = setTimeout(onRevealNext, 250);
      return () => clearTimeout(t);
    }
  }, [isCardFullyDone, onRevealNext]);

  return (
    <div
      className={`term-row${isActive ? ' is-active' : ''}`}
    >
      {/* Main typed line */}
      <button
        type="button"
        className="term-line"
        onClick={() => {
          onSelectFinding?.(finding);
          setExpanded((v) => !v);
        }}
        aria-expanded={expanded}
      >
        {/* Typed content - full problem title displayed */}
        <span className="term-typed-content">
          {displayedTitle}
          {!titleDone && <span className="term-cursor">▋</span>}
        </span>
      </button>

      {/* Expanded detail block */}
      {expanded && (
        <div className="term-detail">
          {/* desc line types in once title is done */}
          {hasDesc && titleDone && (
            <div className="term-detail-line">
              <span className="term-detail-key">desc:</span>
              <span className="term-detail-val">
                {displayedDesc}
                {!descDone && <span className="term-cursor">▋</span>}
              </span>
            </div>
          )}

          {/* Fix block — shows and types once desc is done */}
          {hasFix && titleDone && isDescEffectivelyDone && (
            <div className="term-detail-line">
              <span className="term-detail-key">fix:</span>
              <span className="term-detail-val term-fix-val">
                {displayedFix}
                {!fixDone && <span className="term-cursor">▋</span>}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
