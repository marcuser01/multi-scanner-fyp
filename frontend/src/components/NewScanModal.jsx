// frontend/src/components/NewScanModal.jsx
import React, { useState } from 'react';

export const NewScanModal = ({ onUpload, onCancel }) => {
  const [file, setFile] = useState(null);
  const [config, setConfig] = useState('auto');
  const [taskName, setTaskName] = useState('');
  const [taskDescription, setTaskDescription] = useState('');

  // ALL SUPPORTED CONFIGS
  const configs = [
    { id: 'auto', name: 'Auto Detect (Recommended)' },
    { id: 'owasp', name: 'OWASP Top 10' },
    { id: 'audit', name: 'Security Audit (Deep)' },
    { id: 'python', name: 'Python Specific' },
    { id: 'secrets', name: 'Hardcoded Secrets' }
  ];

  return (
    <div className="p-8 bg-white w-full">
      <h2 className="text-2xl font-black text-slate-800 mb-6">Launch New Triage</h2>
      
      <div className="space-y-4">
        {/* Task Name */}
        <div>
          <label className="block text-xs font-bold text-slate-400 uppercase mb-2">Task Name</label>
          <input 
            type="text" 
            value={taskName}
            onChange={(e) => setTaskName(e.target.value)}
            className="w-full border-2 border-slate-100 p-3 rounded-xl focus:border-blue-500 outline-none"
            placeholder="e.g., Inventory System Audit"
          />
        </div>

        {/* Task Description */}
        <div>
          <label className="block text-xs font-bold text-slate-400 uppercase mb-2">App Context (Sent to RAG)</label>
          <textarea 
            value={taskDescription}
            onChange={(e) => setTaskDescription(e.target.value)}
            className="w-full border-2 border-slate-100 p-3 rounded-xl focus:border-blue-500 outline-none h-24"
            placeholder="What does this app do? (e.g. Healthcare portal handling patient records)"
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          {/* Ruleset Select */}
          <div>
            <label className="block text-xs font-bold text-slate-400 uppercase mb-2">Scanning Ruleset</label>
            <select 
              value={config} 
              onChange={(e) => setConfig(e.target.value)} 
              className="w-full border-2 border-slate-100 p-3 rounded-xl bg-white"
            >
              {configs.map(c => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
          </div>

          {/* File Upload */}
          <div>
            <label className="block text-xs font-bold text-slate-400 uppercase mb-2">Project Source (.ZIP)</label>
            <input 
              type="file" 
              onChange={(e) => setFile(e.target.files[0])} 
              className="text-xs mt-2 block w-full text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-xs file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100" 
            />
          </div>
        </div>
      </div>

      <div className="mt-8 flex space-x-3">
        <button 
          onClick={onCancel} 
          className="flex-1 py-3 font-bold text-slate-400 hover:text-slate-600 transition"
        >
          Cancel
        </button>
        <button 
          onClick={() => onUpload(file, config, taskName, taskDescription)}
          className="flex-1 bg-blue-600 text-white py-3 rounded-2xl font-bold shadow-lg shadow-blue-100 hover:bg-blue-700 transition active:scale-95"
        >
          Start Vulnerability Scan
        </button>
      </div>
    </div>
  );
};