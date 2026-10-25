import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import App from './App';
import './styles.css';

const container = document.getElementById('root');

if (!container) {
  // A missing mount point means index.html and this entry point disagree,
  // which is a build problem rather than a runtime one. Failing loudly beats
  // a blank page with a silent console warning.
  throw new Error('MuleGuard: #root is missing from index.html; the app cannot mount.');
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
