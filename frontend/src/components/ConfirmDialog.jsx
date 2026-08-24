import { useEffect, useRef } from 'react';
import { AlertTriangle } from 'lucide-react';

export default function ConfirmDialog({
  title,
  body,
  children,
  icon: Icon = AlertTriangle,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  danger = false,
  onConfirm,
  onCancel,
  wide = false,
}) {
  const cancelRef = useRef(null);
  const custom = Boolean(children);

  useEffect(() => {
    if (!custom) cancelRef.current?.focus();
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onCancel?.();
      }
    };
    document.addEventListener('keydown', onKey, true);
    return () => document.removeEventListener('keydown', onKey, true);
  }, [onCancel, custom]);

  return (
    <div
      className="confirm-overlay"
      role="presentation"
      onPointerDown={(e) => {
        if (e.target === e.currentTarget) onCancel?.();
      }}
    >
      <div
        className={`confirm-box ${wide ? 'is-wide' : ''}`.trim()}
        role={custom ? 'dialog' : 'alertdialog'}
        aria-modal="true"
        aria-label={title}
        onPointerDown={(e) => e.stopPropagation()}
      >
        <div className="confirm-head">
          <Icon size={18} className={`confirm-icon ${danger ? 'is-danger' : ''}`} />
          <h3>{title}</h3>
        </div>
        {children ?? (
          <>
            {body && <p className="confirm-body">{body}</p>}
            <div className="confirm-actions">
              <button
                type="button"
                ref={cancelRef}
                className="btn btn-secondary"
                onClick={onCancel}
              >
                {cancelLabel}
              </button>
              <button
                type="button"
                className={`btn ${danger ? 'btn-danger' : 'btn-primary'}`}
                onClick={onConfirm}
              >
                {confirmLabel}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
