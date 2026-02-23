import React from 'react';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import Settings from './pages/Settings';

function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-gray-50">
        {/* Sidebar Navigation */}
        <nav className="w-64 bg-slate-900 text-white p-6 shrink-0">
          <h1 className="text-xl font-bold mb-8 text-blue-400">AI Vulnerability Multi-Scanner Platform</h1>
          <div className="space-y-2">
            <Link to="/" className="block py-2 px-4 rounded hover:bg-slate-800 transition">
              Dashboard
            </Link>
            <Link to="/settings" className="block py-2 px-4 rounded hover:bg-slate-800 transition">
              Settings
            </Link>
          </div>
        </nav>

        {/* Main Content Area */}
        <main className="flex-1 p-10 overflow-y-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

// THIS WAS MISSING:
export default App;