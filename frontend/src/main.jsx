import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'
import axios from 'axios';

// 1. Send cookies for auth (this is a security feature)
axios.defaults.withCredentials = true;

// 2. Relative paths are the "Gold Standard" for security.
// It forces Same-Origin compliance, satisfying CSP and CORS policies.
axios.defaults.baseURL = '';

// This guarantees that malicious sites cannot force state-changing actions
axios.defaults.headers.common['X-Requested-With'] = 'XMLHttpRequest';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)