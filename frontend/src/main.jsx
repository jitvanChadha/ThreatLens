import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource-variable/newsreader';
import '@fontsource-variable/ibm-plex-sans';
import '@fontsource/ibm-plex-mono';
import './index.css';
import App from './App.jsx';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
