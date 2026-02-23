import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { NewScanModal } from '../components/NewScanModal';
import { DetailDrawer } from '../components/DetailDrawer';

const Dashboard = () => {
  const [scans, setScans] = useState([]);
  const [showModal, setShowModal] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [findings, setFindings] = useState([]);
  const [activeScanId, setActiveScanId] = useState(null);

  const fetchScans = useCallback(async () => {
    try {
      const res = await axios.get('http://localhost:8000/api/scans');
      setScans(res.data);
    } catch (err) { console.error("Fetch error:", err); }
  }, []);

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, [fetchScans]);

  const handleUpload = async (file, config, taskName, taskDescription) => {
    setShowModal(false);
    if (!file) return;
    const formData = new FormData();
    formData.append('file', file);
    formData.append('config', config);
    formData.append('task_name', taskName);
    formData.append('task_description', taskDescription);
    try {
      const res = await axios.post('http://localhost:8000/api/scans', formData);
      setActiveScanId(res.data.scan_id);
      setFindings([]); 
      setSelectedFinding(null); // Reset selection on new scan upload
      fetchScans();
    } catch (err) { alert("Upload failed."); }
  };

  const loadFindings = async (scanId) => {
    setActiveScanId(scanId);
    setFindings([]); 
    setSelectedFinding(null); // FIX: Clear the previous selection so the list refreshes correctly
    try {
      const res = await axios.get(`http://localhost:8000/api/results/${scanId}/findings`);
      setFindings(res.data);
    } catch (err) { console.error(err); }
  };

  const updateFindingWithAi = (findingId, insight) => {
    setFindings(prev => prev.map(f => f.id === findingId ? { ...f, ai_insight: insight } : f));
  };

  return (
    <div className="flex bg-slate-50 min-h-screen">
      {/* Dashboard Section */}
      <div className={`transition-all duration-500 ease-in-out p-8 ${selectedFinding ? 'w-2/3 border-r' : 'w-full'}`}>
        <div className="max-w-6xl mx-auto">
          {/* Header */}
          <div className="flex justify-between items-center mb-10 bg-white p-8 rounded-[2.5rem] border border-slate-200 shadow-sm">
            <div>
              <h1 className="text-3xl font-black text-slate-900 tracking-tight">Security Center</h1>
              <p className="text-slate-400 font-medium">Vulnerability Assessment & AI Triage</p>
            </div>
            <button onClick={() => setShowModal(true)} className="bg-indigo-600 hover:bg-indigo-700 text-white px-8 py-4 rounded-3xl font-black shadow-lg shadow-indigo-100 transition-all active:scale-95">
              NEW SCAN (+)
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Sidebar: History */}
            <div className="lg:col-span-1 space-y-4">
              <h2 className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] px-2">Recent Scans</h2>
              <div className="space-y-4 max-h-[75vh] overflow-y-auto pr-2">
                {scans.map(scan => (
                  <div key={scan.id} onClick={() => loadFindings(scan.id)} className={`p-6 rounded-[2rem] border-2 cursor-pointer transition-all ${activeScanId === scan.id ? 'border-indigo-500 bg-white shadow-xl' : 'bg-white border-transparent hover:border-slate-200 shadow-sm'}`}>
                    <div className="flex justify-between mb-3">
                      <span className="font-mono text-[9px] text-slate-400 uppercase tracking-tighter">ID: {scan.id.slice(0,8)}</span>
                      <span className={`text-[9px] font-black px-2 py-0.5 rounded-md ${scan.status === 'completed' ? 'bg-green-100 text-green-700' : 'bg-indigo-100 text-indigo-700 animate-pulse'}`}>{scan.status.toUpperCase()}</span>
                    </div>
                    <p className="font-black text-slate-800 text-lg mb-1 truncate">{scan.task_name || "Unnamed Task"}</p>
                    <p className="text-[10px] text-slate-400 italic mb-4">Rules: {scan.config_profile}</p>
                    <div className="flex justify-between items-center pt-4 border-t border-slate-100">
                       <div className="flex flex-col">
                          <span className="text-[9px] font-black text-slate-400 uppercase">Findings</span>
                          <span className="text-xl font-black text-slate-700">{scan.total_findings}</span>
                       </div>
                       <span className="text-[10px] text-slate-300 font-bold">{new Date(scan.scanned_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Findings Grid */}
            <div className="lg:col-span-2">
              <h2 className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] px-2 mb-4">Findings List</h2>
              {!activeScanId ? (
                <div className="h-96 flex flex-col items-center justify-center border-2 border-dashed border-slate-200 rounded-[3rem] bg-white/50 text-slate-300">
                  <span className="text-4xl mb-4">🔍</span>
                  <p className="font-black uppercase tracking-widest text-xs">Select a scan to view data</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-4">
                  {findings.map(f => (
                    <div 
                      key={f.id} 
                      onClick={() => setSelectedFinding(f)} 
                      /* FIX: Updated border classes to ensure layout stays static during selection */
                      className={`bg-white border-2 p-6 rounded-[2rem] transition-all cursor-pointer shadow-sm group ${selectedFinding?.id === f.id ? 'border-indigo-500 ring-4 ring-indigo-50 shadow-xl' : 'border-white hover:border-indigo-100'}`}
                    >
                      <div className="flex justify-between items-center">
                        <div>
                          <div className="flex items-center space-x-3 mb-2">
                            <span className={`text-[9px] font-black px-2 py-1 rounded-md ${f.severity === 'HIGH' ? 'bg-red-100 text-red-600' : 'bg-orange-100 text-orange-600'}`}>{f.severity}</span>
                            <span className="text-[9px] font-black text-slate-300 uppercase tracking-widest">Semgrep CE</span>
                          </div>
                          <h3 className="font-black text-slate-800 text-lg group-hover:text-indigo-600">{cleanTitle(f.title)}</h3>
                          <p className="text-[10px] text-slate-400 mt-2 font-mono">{f.file_path.split('/').pop()} | Line {f.line_number}</p>
                        </div>
                        <div className="text-indigo-600 font-black text-[10px] uppercase group-hover:translate-x-1 transition-transform">View Details &rarr;</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Side Pane */}
      {selectedFinding && (
        <div className="w-1/3 bg-white border-l border-slate-200 shadow-2xl overflow-hidden sticky top-0 h-screen">
          <DetailDrawer 
            finding={selectedFinding} 
            onClose={() => setSelectedFinding(null)} 
            onUpdate={updateFindingWithAi} 
          />
        </div>
      )}

      {/* Modal Overlay */}
      {showModal && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-md flex items-center justify-center z-50 p-6">
          <div className="bg-white rounded-[3rem] shadow-2xl w-full max-w-lg overflow-hidden relative">
            <NewScanModal onUpload={handleUpload} onCancel={() => setShowModal(false)} />
          </div>
        </div>
      )}
    </div>
  );
};

const cleanTitle = (title) => {
  if (!title) return "Unknown Finding";
  const parts = title.split('.');
  const lastPart = parts[parts.length - 1];
  return lastPart.replace(/-/g, ' ').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
};

export default Dashboard;