import React, { useState, useContext } from 'react';
import { AuthContext } from '../App';

export const NewScanModal = ({ onUpload, onCancel }) => {
  const { user } = useContext(AuthContext); // Get Role
  const [file, setFile] = useState(null);
  const [scanLevel, setScanLevel] = useState('standard');
  const [taskName, setTaskName] = useState('');
  const [taskDescription, setTaskDescription] = useState('');
  const [scanners, setScanners] = useState({ sast: true, sca: true, dast: false });
  const [targetUrl, setTargetUrl] = useState('');
  const [dastMode, setDastMode] = useState('baseline'); // 'baseline' (safe) or 'full' (aggressive)

  const scanLevels = [
    { id: 'quick', name: 'Quick Scan', desc: 'Fast, baseline checks', time: '~1 min' },
    { id: 'standard', name: 'Standard', desc: 'Full OWASP Top 10', time: '~3 mins' },
    { id: 'deep', name: 'Deep Audit', desc: 'Secrets & deep rule logic', time: '~10+ mins' }
  ];

  const dastModes = [
    {
      id: 'baseline',
      name: 'Safe Scan (Passive)',
      desc: 'Analyzes headers, cookies, and source code. No active exploit payloads are sent.',
      color: 'border-slate-200 hover:border-blue-400 bg-white'
    },
    {
      id: 'full',
      name: 'Active Intrusion (Aggressive)',
      desc: 'Injects real exploit payloads (SQLi, XSS). WARNING: May impact fragile staging databases.',
      color: 'border-red-200 hover:border-red-400 bg-red-50/10'
    }
  ];

  const engineDetails = {
    sast: {
      title: "Code Audit",
      subtitle: "SAST // Semgrep",
      desc: "Scans raw files for structural code bugs."
    },
    sca: {
      title: "Dependency Scan",
      subtitle: "SCA // Trivy",
      desc: "Scans libraries and packages for known CVEs."
    },
    dast: {
      title: "Web Attack",
      subtitle: "DAST // OWASP ZAP",
      desc: "Simulates attacks against active runtime URLs."
    }
  };

  const toggleScanner = (type) => setScanners(prev => ({ ...prev, [type]: !prev[type] }));
  const hasScannerSelected = scanners.sast || scanners.sca || scanners.dast;
  const needsFile = scanners.sast || scanners.sca;
  const isFormValid = hasScannerSelected && (!needsFile || file !== null) && (!scanners.dast || targetUrl.trim() !== '');

  return (
    // container has strict max-height and flex-col layout to lock action buttons to footer
    <div className="flex flex-col h-[85vh] w-full text-slate-800 bg-white rounded-3xl overflow-hidden shadow-2xl">
      
      {/* 1. FIXED HEADER */}
      <div className="px-8 py-6 shrink-0 border-b border-slate-100 bg-white">
        <h2 className="text-3xl font-black text-slate-900 tracking-tight leading-tight">Configure Assessment</h2>
        <p className="text-sm font-semibold text-slate-500 mt-1.5">Define your multi-scanner pipeline scope and targets</p>
      </div>

      {/* 2. SCROLLABLE MIDDLE FORM AREA */}
      <div className="flex-1 overflow-y-auto px-8 py-6 space-y-6 custom-scrollbar bg-slate-50/30">
        
        {/* Section 1: Identity & Context */}
        <div className="bg-white p-5 rounded-2xl border border-slate-100 shadow-sm space-y-4">
          {/* UPGRADED: Expanded Section Header Badge Sizing & Padding */}
          <h3 className="text-xs font-black text-blue-600 uppercase tracking-widest bg-blue-50 px-4 py-2 rounded-lg inline-block">1. General Information</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="col-span-1">
              <label className="block text-[11px] font-bold text-slate-700 uppercase mb-2 tracking-wider">Task Title *</label>
              <input 
                type="text" 
                value={taskName} 
                onChange={(e) => setTaskName(e.target.value)} 
                className="w-full border border-slate-200 p-2.5 rounded-xl text-xs font-semibold outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-100 transition" 
                placeholder="e.g., Q3 Release Audit" 
                required
              />
            </div>
            <div className="col-span-1 md:col-span-2">
              <label className="block text-[11px] font-bold text-slate-700 uppercase mb-2 tracking-wider">Business Context (Passed to AI)</label>
              <input 
                type="text" 
                value={taskDescription} 
                onChange={(e) => setTaskDescription(e.target.value)} 
                className="w-full border border-slate-200 p-2.5 rounded-xl text-xs font-semibold outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-100 transition" 
                placeholder="e.g. Node.js backend handling clinical patient records" 
              />
            </div>
          </div>
        </div>

        {/* Section 2: Security Engines Selection */}
        <div className="bg-white p-5 rounded-2xl border border-slate-100 shadow-sm space-y-4">
          {/* UPGRADED: Expanded Section Header Badge Sizing & Padding */}
          <h3 className="text-xs font-black text-blue-600 uppercase tracking-widest bg-blue-50 px-4 py-2 rounded-lg inline-block">2. Analysis Scope</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {Object.entries(engineDetails).map(([type, info]) => (
              <button
                key={type}
                type="button"
                onClick={() => toggleScanner(type)}
                className={`p-4 rounded-xl border-2 transition-all text-left flex flex-col justify-between min-h-[140px] ${
                  scanners[type] 
                    ? 'border-blue-600 bg-blue-50/60 ring-2 ring-blue-100 shadow-sm' 
                    : 'border-slate-200 bg-white hover:border-slate-300'
                }`}
              >
                <div className="w-full">
                  <div className="flex justify-between items-center mb-1">
                    <span className="font-bold text-sm text-slate-900">{info.title}</span>
                    <div className={`w-4 h-4 rounded-full border-2 flex items-center justify-center ${scanners[type] ? 'border-blue-600 bg-blue-600' : 'border-slate-300'}`}>
                      {scanners[type] && <div className="w-1.5 h-1.5 bg-white rounded-full"></div>}
                    </div>
                  </div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-2">{info.subtitle}</span>
                  <p className="text-xs text-slate-500 font-medium leading-relaxed">{info.desc}</p>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Section 3: Depth Selection */}
        <div className="bg-white p-5 rounded-2xl border border-slate-100 shadow-sm space-y-4">
          {/* UPGRADED: Expanded Section Header Badge Sizing & Padding */}
          <h3 className="text-xs font-black text-blue-600 uppercase tracking-widest bg-blue-50 px-4 py-2 rounded-lg inline-block">3. Audit Depth</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {scanLevels.map(lvl => (
              <div 
                key={lvl.id} 
                onClick={() => setScanLevel(lvl.id)} 
                className={`cursor-pointer p-4 rounded-xl border-2 flex justify-between items-center transition-all ${
                  scanLevel === lvl.id 
                    ? 'border-blue-600 bg-blue-50/30 shadow-sm' 
                    : 'border-slate-200 hover:border-blue-300 bg-white'
                }`}
              >
                <div>
                  <h4 className={`font-bold text-sm ${scanLevel === lvl.id ? 'text-blue-800' : 'text-slate-800'}`}>{lvl.name}</h4>
                  <p className="text-xs text-slate-500 font-medium mt-0.5 leading-relaxed">{lvl.desc}</p>
                </div>
                <span className="text-[10px] font-black bg-white px-2 py-1 rounded text-slate-500 border">{lvl.time}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Section 4: DAST Intrusion Setting */}
        {scanners.dast && (
          <div className="bg-white p-5 rounded-2xl border border-slate-100 shadow-sm space-y-4 animate-in fade-in duration-300">
            <div className="flex justify-between items-center border-b border-slate-100 pb-3">
              {/* UPGRADED: Expanded Warning Pill-Badge Header */}
              <h3 className="text-xs font-black text-red-600 uppercase tracking-widest bg-red-50 px-4 py-2 rounded-lg inline-block">4. DAST Safety Guard</h3>
              {user.role === 'DEVELOPER' && (
                <span className="text-[9px] font-black bg-red-100 text-red-700 px-2 py-0.5 rounded border border-red-200 uppercase tracking-wider">Restricted by Admin</span>
              )}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {dastModes.map(mode => {
                const isDisabled = mode.id === 'full' && user.role === 'DEVELOPER';
                return (
                  <div 
                    key={mode.id} 
                    onClick={() => !isDisabled && setDastMode(mode.id)} 
                    className={`p-4 rounded-xl border-2 transition-all flex items-start gap-3 
                    ${isDisabled ? 'opacity-40 cursor-not-allowed border-slate-200 bg-slate-100' : 
                      dastMode === mode.id ? 'border-red-500 bg-red-50/10 cursor-pointer shadow-sm' : mode.color + ' cursor-pointer'}`}
                  >
                    <input type="radio" checked={dastMode === mode.id} disabled={isDisabled} onChange={() => {}} className="mt-1 accent-red-600" />
                    <div>
                      <h4 className={`font-bold text-sm ${dastMode === mode.id ? 'text-red-900 font-black' : 'text-slate-800'}`}>{mode.name}</h4>
                      <p className="text-xs text-slate-500 font-medium mt-1 leading-relaxed">{mode.desc}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Section 5: Target Inputs */}
        {hasScannerSelected && (
          <div className="bg-white p-5 rounded-2xl border border-slate-100 shadow-sm space-y-5 animate-in fade-in duration-300">
            {/* UPGRADED: Expanded Action Target Pill-Badge Header */}
            <h3 className="text-xs font-black text-emerald-600 uppercase tracking-widest bg-emerald-50 px-4 py-2 rounded-lg inline-block">5. Target Details</h3>
            
            {needsFile && (
              <div className="space-y-3">
                <label className="block text-[11px] font-black text-slate-500 uppercase tracking-wider">Project Source Code Archive (.ZIP) *</label>
                <div className="text-xs text-blue-800 bg-blue-50/50 border border-blue-100 p-3 rounded-xl leading-relaxed font-medium">
                  💡 <b>Upload ZIP:</b> Please pack your folder and drop it below. Include lockfiles (e.g., <i>package-lock.json</i>) for optimal analysis.
                </div>
                <input 
                  type="file" 
                  accept=".zip" 
                  onChange={(e) => setFile(e.target.files[0])} 
                  className="block w-full text-xs text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-xl file:border-0 file:text-[10px] file:font-black file:bg-blue-100 file:text-blue-700 cursor-pointer" 
                />
              </div>
            )}

            {scanners.dast && (
              <div className={`space-y-3 ${needsFile ? 'border-t border-slate-100 pt-5' : ''}`}>
                <label className="block text-[11px] font-black text-slate-500 uppercase tracking-wider">Target Application URL *</label>
                <div className="text-xs text-emerald-800 bg-emerald-50/50 border border-emerald-100 p-3 rounded-xl leading-relaxed font-medium">
                  💡 <b>Endpoint URL:</b> Input the exact address (e.g., <i>https://staging.myapp.com</i>) of your running system.
                </div>
                <input 
                  type="url" 
                  value={targetUrl} 
                  onChange={(e) => setTargetUrl(e.target.value)} 
                  className="w-full border border-slate-300 p-3 rounded-xl text-xs font-semibold outline-none focus:border-blue-500 transition" 
                  placeholder="https://staging.myapp.com" 
                />
              </div>
            )}
          </div>
        )}
      </div>

      {/* 3. FIXED ACTIONS FOOTER (Fully balanced spacing) */}
      <div className="px-8 py-6 shrink-0 border-t border-slate-100 bg-slate-50 flex gap-3 z-10">
        <button 
          onClick={onCancel} 
          className="w-1/3 py-3 font-bold text-slate-500 hover:bg-slate-200 hover:text-slate-800 rounded-xl text-xs uppercase tracking-widest transition"
        >
          Cancel
        </button>
        <button 
          disabled={!isFormValid} 
          onClick={() => onUpload(file, scanLevel, taskName, taskDescription, scanners, targetUrl, dastMode)} 
          className="w-2/3 bg-blue-600 text-white py-3 rounded-xl font-black shadow-lg hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition uppercase text-xs tracking-widest"
        >
          Start Security Scan
        </button>
      </div>

    </div>
  );
};