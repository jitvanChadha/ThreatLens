import { useState, useEffect, useRef } from 'react';

/**
 * Typewriter hook — types `text` character-by-character.
 *
 * @param {string}  text        Full string to type
 * @param {number}  speed       Milliseconds per character (default 28ms)
 * @param {number}  startDelay  Milliseconds to wait before starting (default 0)
 * @returns {{ displayed: string, done: boolean }}
 */
export function useTypewriter(text = '', speed = 28, startDelay = 0, enabled = true) {
  const [displayed, setDisplayed] = useState('');
  const [done, setDone] = useState(false);
  const indexRef = useRef(0);
  const timerRef = useRef(null);

  useEffect(() => {
    setDisplayed('');
    setDone(false);
    indexRef.current = 0;

    if (!enabled || !text) {
      return;
    }

    const startTimer = setTimeout(() => {
      timerRef.current = setInterval(() => {
        indexRef.current += 1;
        const slice = text.slice(0, indexRef.current);
        setDisplayed(slice);

        if (indexRef.current >= text.length) {
          clearInterval(timerRef.current);
          setDone(true);
        }
      }, speed);
    }, startDelay);

    return () => {
      clearTimeout(startTimer);
      clearInterval(timerRef.current);
    };
  }, [text, speed, startDelay, enabled]);

  return { displayed, done };
}
