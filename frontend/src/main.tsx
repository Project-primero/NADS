import React from 'react';
import ReactDOM from 'react-dom/client';
import { Dashboard } from './components/Dashboard';
import { initTheme } from './lib/themes';
import './index.css';

initTheme();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode><Dashboard /></React.StrictMode>
);
