import { useCallback, useEffect, useRef } from 'react';

export function clampWidth(px, { min, max, reserve, viewportW }) {
  const ceiling = typeof max === 'function' ? max(viewportW) : max;
  const keep = typeof reserve === 'function' ? reserve() : reserve;
  const hardMax = Math.min(ceiling, Math.max(min, viewportW - keep));
  return Math.round(Math.min(hardMax, Math.max(min, px)));
}

export default function useSplitter({
  varName = '--split-w',
  storageKey = 'threatlens_split_w',
  initial = 580,
  min = 340,
  max = 1100,
  fromRight = false,
  reserve = 360,
  ref = null,
}) {
  const ownRef = useRef(null);
  const containerRef = ref || ownRef;

  const clamp = useCallback(
    (px) => clampWidth(px, { min, max, reserve, viewportW: window.innerWidth }),
    [min, max, reserve],
  );

  useEffect(() => {
    let stored = null;
    try {
      stored = localStorage.getItem(storageKey);
    } catch { /* ignored */ }
    const px = clamp(parseInt(stored ?? '', 10) || initial);
    if (containerRef.current) {
      containerRef.current.style.setProperty(varName, `${px}px`);
    }
  }, [varName, storageKey, initial, clamp, containerRef]);

  const onPointerDown = useCallback((e) => {
    e.preventDefault();
    const grip = e.currentTarget;
    const container = containerRef.current;
    if (!container) return;

    grip.classList.add('is-dragging');
    grip.setPointerCapture?.(e.pointerId);
    const prevCursor = document.body.style.cursor;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';

    const move = (ev) => {
      const box = container.getBoundingClientRect();
      const px = fromRight ? box.right - ev.clientX : ev.clientX - box.left;
      container.style.setProperty(varName, `${clamp(px)}px`);
    };

    const up = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      window.removeEventListener('pointercancel', up);
      grip.classList.remove('is-dragging');
      document.body.style.cursor = prevCursor;
      document.body.style.userSelect = '';
      try {
        const v = container.style.getPropertyValue(varName);
        if (v) localStorage.setItem(storageKey, parseInt(v, 10));
      } catch { /* ignored */ }
    };

    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
    window.addEventListener('pointercancel', up);
  }, [varName, storageKey, clamp, fromRight, containerRef]);

  const onKeyDown = useCallback((e) => {
    const container = containerRef.current;
    if (!container) return;
    const step = e.shiftKey ? 40 : 16;
    const current = parseInt(container.style.getPropertyValue(varName), 10) || initial;
    let next = null;
    if (e.key === 'ArrowLeft') next = current + (fromRight ? step : -step);
    if (e.key === 'ArrowRight') next = current + (fromRight ? -step : step);
    if (next === null) return;
    e.preventDefault();
    const px = clamp(next);
    container.style.setProperty(varName, `${px}px`);
    try {
      localStorage.setItem(storageKey, px);
    } catch { /* ignored */ }
  }, [varName, storageKey, initial, clamp, fromRight, containerRef]);

  return { containerRef, onPointerDown, onKeyDown };
}
