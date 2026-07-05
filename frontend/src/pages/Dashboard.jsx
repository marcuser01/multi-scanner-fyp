import React, { useState, useEffect, useCallback, useContext } from 'react';
import axios from 'axios';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import ReactMarkdown from 'react-markdown';
import { NewScanModal } from '../components/NewScanModal';
import { DetailDrawer } from '../components/DetailDrawer';
import { AuthContext } from '../App';

const SEV_STYLES = {
  CRITICAL: 'bg-red-100 text-red-800 border-red-300 ring-red-300',
  HIGH: 'bg-orange-100 text-orange-800 border-orange-300 ring-orange-300',
  MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-300 ring-yellow-300',
  LOW: 'bg-blue-100 text-blue-800 border-blue-300 ring-blue-300',
  INFO: 'bg-slate-100 text-slate-800 border-slate-300 ring-slate-300'
};
const CHART_COLORS = { CRITICAL: '#991b1b', HIGH: '#ea580c', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#94a3b8' };
const SEV_WEIGHT = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

export default function Dashboard() {
  const { user } = useContext(AuthContext); 
  const [scans, setScans] = useState([]);
  const [activeScan, setActiveScan] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  const [scanDetails, setScanDetails] = useState(null);
  const [issues, setIssues] = useState([]);
  const [selectedIssue, setSelectedIssue] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [generatingReport, setGeneratingReport] = useState(false);

  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterScanner, setFilterScanner] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const fetchScans = useCallback(async () => {
    try {
      const res = await axios.get('/api/scans');
      setScans(res.data || []);

      // Smart Polling Update Logic
      if (activeScan) {
        const updatedScan = (res.data || []).find(s => s && s.id === activeScan.id);
        if (updatedScan && updatedScan.status !== activeScan.status) {
          setActiveScan(updatedScan);
          // If state flipped to analyzing or completed, fetch new data!
          if (['analyzing', 'completed'].includes(updatedScan.status)) {
            loadScanData(updatedScan.id);
          }
        }
      }
    } catch (err) { console.error("Polling error, backend might be busy:", err); }
  }, [activeScan]);

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 3000);
    return () => clearInterval(interval);
  }, [fetchScans]);

  const loadScanData = async (scanId) => {
    try {
      const res = await axios.get(`/api/results/${scanId}/correlated`);
      
      // OPTIMIZATION: Robust scanners_json parsing normalization.
      // This protects the UI from database serialization quirks (string vs parsed object).
      const scan = {
        ...res.data.scan,
        scanners_json: typeof res.data.scan.scanners_json === 'string'
          ? JSON.parse(res.data.scan.scanners_json)
          : (res.data.scan.scanners_json || {})
      };

      setScanDetails(scan);
      const sortedIssues = (res.data.issues || []).sort((a, b) => (SEV_WEIGHT[b.primary_severity] || 0) - (SEV_WEIGHT[a.primary_severity] || 0));
      setIssues(sortedIssues);
    } catch (err) { console.error(err); }
  };

  const handleSelectScan = (scan) => {
    setActiveScan(scan);
    setSelectedIssue(null);
    setActiveTab('overview');
    if (scan && ['analyzing', 'completed'].includes(scan.status)) {
      loadScanData(scan.id);
    } else {
      setScanDetails(null);
      setIssues([]);
    }
  };

  const handleGenerateReport = async () => {
    setGeneratingReport(true);
    try {
      const res = await axios.post(`/api/results/${activeScan.id}/generate-report`);
      setScanDetails(prev => ({ ...prev, executive_summary: res.data.summary }));
    } catch (err) {
      const errMsg = err.response?.data?.detail || "Failed to generate report.";
      alert(`⚠️ AI Summary Error\n\n${errMsg}`);
    }
    setGeneratingReport(false);
  };

  const handleDownloadPDF = async () => {
    try {
      const res = await axios.get(`/api/results/${activeScan.id}/report/pdf`, { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `Security_Report_${activeScan?.id ? activeScan.id.slice(0,8) : 'Scan'}.pdf`);
      document.body.appendChild(link);
      link.click();
    } catch (err) {
      // SECURITY FIX: Decodes JSON error payloads wrapped inside binary Blobs
      if (err.response && err.response.data instanceof Blob) {
        const reader = new FileReader();
        reader.onload = () => {
          try {
            const errorJson = JSON.parse(reader.result);
            alert(`⚠️ PDF Export Failed\n\n${errorJson.detail || "Check backend logs."}`);
          } catch (e) {
            alert("⚠️ PDF Export Failed\n\nCould not compile security report. Check backend logs.");
          }
        };
        reader.readAsText(err.response.data);
      } else {
        const errMsg = err.response?.data?.detail || "Failed to generate PDF. Check backend logs.";
        alert(`⚠️ PDF Export Failed\n\n${errMsg}`);
      }
    }
  };

  const handleDeleteScan = async () => {
    if (!window.confirm(`⚠️ CRITICAL PURGE ACTION\n\nAre you sure you want to permanently delete scan "${activeScan.task_name}"?\nThis will purge all findings, database records, and physical PDF assets. This action is non-reversible.`)) {
      return;
    }
    try {
      await axios.delete(`/api/scans/${activeScan.id}`);
      // Clean up React State cleanly to prevent null render/white-screen crashes
      setIssues([]);
      setScanDetails(null);
      setSelectedIssue(null);
      setActiveScan(null);
      fetchScans(); // Refresh historical sidebar list
    } catch (err) {
      alert(err.response?.data?.detail || "Scan purge failed.");
    }
  };

  const handleUpload = async (file, scanLevel, taskName, taskDescription, scanners, targetUrl, dastMode) => {
    setShowModal(false); // Close modal

    const formData = new FormData();
    if (file) formData.append('file', file);
    formData.append('scanLevel', scanLevel);
    formData.append('task_name', taskName);
    formData.append('task_description', taskDescription);
    formData.append('scanners_json', JSON.stringify(scanners));
    if (targetUrl) formData.append('target_url', targetUrl);
    formData.append('dast_mode', dastMode);

    try {
      const res = await axios.post('/api/scans', formData);
      const newScanObj = { id: res.data.scan_id, status: 'running', task_name: taskName };
      setActiveScan(newScanObj);
      setScanDetails(null);
      setIssues([]);
      setSelectedIssue(null);
      fetchScans();
    } catch (err) {
      // ROBUST ERROR PARSING
      let errorMessage = "Failed to start scan. Ensure backend is running.";
      
      if (err.response && err.response.data) {
        const detail = err.response.data.detail;
        if (typeof detail === 'string') {
          errorMessage = detail;
        } else if (Array.isArray(detail)) {
          // Handle FastAPI validation/formatting errors
          errorMessage = detail.map(d => `${d.loc.join('.')}: ${d.msg}`).join('\n');
        } else if (typeof err.response.data.message === 'string') {
          errorMessage = err.response.data.message;
        }
      }
      alert(`⚠️ Scan Request Rejected\n\n${errorMessage}`);
    }
  };

  const updateIssueWorkflow = async (issueId, payload) => {
    try {
      await axios.patch(`/api/results/${issueId}/workflow`, payload);
      setIssues(prev => (prev || []).map(iss => iss.id === issueId ? { ...iss, ...payload } : iss));
    } catch (err) { console.error("Failed to update workflow", err); }
  };

  const getChartData = () => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    (issues || []).forEach(i => { if (i && counts[i.primary_severity] !== undefined) counts[i.primary_severity]++; });
    return Object.keys(counts).filter(k => counts[k] > 0).map(k => ({ name: k, value: counts[k] }));
  };

  // --- HARDENED DERIVED STATES (Handles null/undefined arrays securely) ---

  const hasActiveScan = (scans || []).some(s => s && ['running', 'analyzing'].includes(s.status));

  const filteredIssues = (issues || []).filter(i => {
    if (!i) return false;
    const matchSev = filterSeverity === 'ALL' || i.primary_severity === filterSeverity;
    const matchScanner = filterScanner === 'ALL' || (i.findings || []).some(f => f.scanner_type === filterScanner);
    const matchSearch = (i.title || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (i.cwe && i.cwe.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchSev && matchScanner && matchSearch;
  });

  return (
    <div className="flex bg-slate-100 min-h-screen text-slate-900 overflow-hidden">
      <div className={`transition-all duration-300 ease-in-out p-6 h-screen overflow-y-auto ${selectedIssue ? 'w-2/3' : 'w-full'}`}>

        {/* HEADER */}
        <div className="flex justify-between items-center mb-6 bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
          <div>
            <h1 className="text-3xl font-black text-slate-800 tracking-tight">Riskwise Security</h1>
            <p className="text-slate-500 font-medium text-sm mt-1">Multi-Scanner Posture & AI Triage Dashboard</p>
          </div>
          {/* Visual Lock Implementation */}
          <button 
            disabled={hasActiveScan}
            onClick={() => setShowModal(true)} 
            className={`px-6 py-3 rounded-xl font-bold shadow transition uppercase text-sm select-none ${
              hasActiveScan 
                ? 'bg-slate-300 text-slate-500 cursor-not-allowed shadow-none border border-slate-300' 
                : 'bg-blue-600 text-white hover:bg-blue-700 hover:shadow-lg'
            }`}
          >
            {hasActiveScan ? '🔒 Scan In Progress' : '+ New Scan'}
          </button>
        </div>


        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* SIDEBAR: History */}
          <div className="col-span-1 space-y-3">
            <h2 className="text-xs font-black text-slate-500 uppercase tracking-widest px-2">History</h2>
            <div className="space-y-3 pb-24">
              {(scans || []).map(s => {
                if (!s) return null;
                return (
                <div key={s.id} onClick={() => handleSelectScan(s)}
                  className={`p-4 rounded-xl border-2 cursor-pointer transition ${activeScan?.id === s.id ? 'border-blue-500 bg-blue-50 shadow-md' : 'bg-white border-slate-200 hover:border-slate-300'}`}>
                  <div className="flex justify-between items-center mb-2">
                    {/* HARDENING: Null-pointer check on ID slice to prevent white-screen crashes */}
                    <span className="text-xs text-slate-500 font-mono">{s.id ? s.id.slice(0,8) : 'Unknown'}</span>
                    {s.status === 'running' ? (
                      <span className="text-[10px] font-black uppercase text-blue-600 bg-blue-100 px-2 py-0.5 rounded animate-pulse shadow-sm">Running</span>
                    ) : s.status === 'analyzing' ? (
                      <span className="text-[10px] font-black uppercase text-purple-600 bg-purple-100 px-2 py-0.5 rounded animate-pulse shadow-sm">AI Triage</span>
                    ) : s.status === 'failed' ? (
                      <span className="text-[10px] font-black uppercase text-red-600 bg-red-100 px-2 py-0.5 rounded">Failed</span>
                    ) : (
                      <span className="text-[10px] font-black uppercase text-green-700 bg-green-100 px-2 py-0.5 rounded">Done</span>
                    )}
                  </div>
                  <h3 className="font-bold text-slate-800 text-sm truncate">{s.task_name || "Unnamed Scan"}</h3>
                  <p className="text-xs text-slate-500 mt-1">{s.scanned_at ? new Date(s.scanned_at).toLocaleDateString() : 'N/A'}</p>
                </div>
              )})}
              {(scans || []).length === 0 && (
                <div className="text-center py-6 text-slate-400 italic text-xs">No scan history found.</div>
              )}
            </div>
          </div>

          {/* MAIN PANELS */}
          <div className="col-span-3 pb-24">
            {(scans || []).length === 0 ? (
              <div className="h-[60vh] flex flex-col items-center justify-center border-2 border-dashed border-slate-300 rounded-2xl bg-white text-slate-400 p-8 text-center shadow-sm">
                <span className="text-6xl mb-4">🚀</span>
                <h2 className="text-2xl font-black text-slate-800 mb-2">Welcome to Riskwise Security!</h2>
                <p className="text-sm text-slate-500 max-w-sm mb-6 leading-relaxed">
                  You haven't executed any security scans yet. Click below to launch your first automated multi-scanner pipeline.
                </p>
                <button onClick={() => setShowModal(true)} className="bg-blue-600 text-white px-6 py-3 rounded-xl font-bold shadow hover:bg-blue-700 transition uppercase text-xs tracking-wider">
                  Launch First Scan
                </button>
              </div>
            ) : !activeScan ? (
              <div className="h-[60vh] flex flex-col items-center justify-center border-2 border-dashed border-slate-300 rounded-2xl bg-white text-slate-400">
                <span className="text-6xl mb-4">📊</span>
                <p className="font-black uppercase tracking-widest text-sm">Select a scan from history to view data</p>
              </div>
            ) : activeScan.status === 'running' ? (
              <div className="h-[60vh] flex flex-col items-center justify-center border-2 border-slate-300 rounded-2xl bg-white text-slate-800 shadow-sm">
                <div className="animate-spin rounded-full h-16 w-16 border-t-4 border-b-4 border-blue-600 mb-6"></div>
                <h2 className="text-2xl font-black mb-2">Engines Scanning...</h2>
                <p className="text-slate-500 font-medium text-sm text-center max-w-sm">
                  Executing SAST, SCA, and DAST engines asynchronously. This can take a few minutes.
                </p>
              </div>
            ) : activeScan.status === 'failed' ? (
              <div className="h-[60vh] flex flex-col items-center justify-center border-2 border-red-300 rounded-2xl bg-red-50 text-red-800 p-8 text-center">
                <span className="text-6xl mb-4">⚠️</span>
                <h2 className="text-2xl font-black mb-2">Scan Failed</h2>
                <p className="text-sm font-bold text-red-600 bg-white px-4 py-3 rounded-xl border border-red-200 mt-2 max-w-lg shadow-sm">
                   {activeScan.error_message || "An unknown error occurred during execution. Check system audit logs."}
                </p>
                {/* FIX: Render "Purge Scan" button inside the Failure box, visible ONLY to ADMINs */}
                {user?.role === 'ADMIN' && (
                  <button onClick={handleDeleteScan} className="mt-6 text-xs bg-red-100 text-red-700 border border-red-200 font-bold px-4 py-2 rounded-lg hover:bg-red-200 transition uppercase tracking-wider">
                    Purge Failed Scan
                  </button>
                )}
              </div>
            ) : (
              <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
                {/* TABS */}
                <div className="flex border-b border-slate-200 bg-slate-50">
                  {['overview', 'findings', 'vuln management'].map(tab => (
                    <button key={tab} onClick={() => setActiveTab(tab)} className={`px-6 py-4 font-black uppercase tracking-wider text-xs transition ${activeTab === tab ? 'text-blue-700 border-b-2 border-blue-600 bg-white' : 'text-slate-500 hover:text-slate-800 hover:bg-slate-100'}`}>
                      {tab}
                    </button>
                  ))}
                </div>

                <div className="p-6">
                  {/* OVERVIEW TAB */}
                  {activeTab === 'overview' && scanDetails && (
                    <div className="space-y-8">
                      {/* Scan Configuration & Detailed Metadata Card */}
                      <div className="bg-slate-50 rounded-xl p-6 border border-slate-200">
                        <h3 className="text-sm font-black text-slate-800 uppercase tracking-widest mb-4">Scan Configurations & Metadata</h3>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-sm">
                          <div>
                            <span className="text-slate-500 font-bold block mb-1">Target Name & Depth</span>
                            <span className="font-bold text-slate-900">{scanDetails?.task_name}</span>
                            <span className="ml-2 bg-blue-100 text-blue-800 px-2 py-0.5 rounded text-xs font-black uppercase">{scanDetails?.scan_level}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 font-bold block mb-1">Audit Date</span>
                            <span className="font-semibold text-slate-900">{scanDetails?.scanned_at ? new Date(scanDetails.scanned_at).toLocaleString() : ''}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 font-bold block mb-1">Target URL (DAST)</span>
                            <span className="font-semibold text-slate-900 break-all">{scanDetails?.target_url || 'N/A (Local Filesystem Scan)'}</span>
                          </div>
                          
                          <div className="col-span-1 md:col-span-3 border-t border-slate-200 pt-4">
                            <span className="text-slate-500 font-bold block mb-2">Enabled Engines</span>
                            <div className="flex gap-2 flex-wrap">
                              <span className={`text-xs px-2.5 py-1 rounded font-black ${scanDetails?.scanners_json?.sast ? 'bg-blue-100 text-blue-800 border border-blue-200' : 'bg-slate-100 text-slate-400 line-through'}`}>
                                SAST Code Audit
                              </span>
                              <span className={`text-xs px-2.5 py-1 rounded font-black ${scanDetails?.scanners_json?.sca ? 'bg-purple-100 text-purple-800 border border-purple-200' : 'bg-slate-100 text-slate-400 line-through'}`}>
                                SCA Dependency Scan
                              </span>
                              <span className={`text-xs px-2.5 py-1 rounded font-black ${scanDetails?.scanners_json?.dast ? 'bg-emerald-100 text-emerald-800 border border-emerald-200' : 'bg-slate-100 text-slate-400 line-through'}`}>
                                DAST Web Attack {scanDetails?.scanners_json?.dast && `(${scanDetails?.dast_mode || 'baseline'})`}
                              </span>
                            </div>
                          </div>

                          <div className="col-span-1 md:col-span-3 border-t border-slate-200 pt-4">
                            <span className="text-slate-500 font-bold block mb-1">Target Business Context</span>
                            <p className="text-slate-700 bg-white p-3 rounded-xl border border-slate-200 text-xs leading-relaxed italic">{scanDetails?.task_description || 'No business context provided.'}</p>
                          </div>
                        </div>
                      </div>

                      {issues.length === 0 ? (
                        <div className="text-center py-10 bg-green-50 border border-green-200 rounded-xl">
                          <span className="text-5xl">🎉</span>
                          <h3 className="text-xl font-black text-green-800 mt-4">100% Secure!</h3>
                          <p className="text-green-700 mt-2">No vulnerabilities were detected by any scanners.</p>
                        </div>
                      ) : (
                        <div className="grid grid-cols-3 gap-6">
                          <div className="col-span-1 h-48">
                            <ResponsiveContainer width="100%" height="100%">
                              <PieChart>
                                <Pie data={getChartData()} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                                  {getChartData().map((entry, index) => <Cell key={`cell-${index}`} fill={CHART_COLORS[entry.name]} />)}
                                </Pie>
                                <Tooltip />
                              </PieChart>
                            </ResponsiveContainer>
                          </div>
                          <div className="col-span-2 grid grid-cols-2 gap-4">
                            <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 flex flex-col justify-center">
                              <span className="text-sm font-bold text-slate-500 uppercase">Total Issues</span>
                              <span className="text-5xl font-black text-slate-800">{issues.length}</span>
                            </div>
                            <div className="bg-red-50 p-4 rounded-xl border border-red-200 flex flex-col justify-center">
                              <span className="text-sm font-bold text-red-600 uppercase">Critical / High</span>
                              <span className="text-5xl font-black text-red-700">{issues.filter(i => i && ['CRITICAL','HIGH'].includes(i.primary_severity)).length}</span>
                            </div>
                          </div>
                        </div>
                      )}

                      <div className="border-t border-slate-200 pt-6">
                        <div className="flex justify-between items-center mb-4">
                          <h3 className="text-lg font-black text-slate-800">AI Executive Summary</h3>
                          <div className="flex gap-3">
                            {!generatingReport && (
                              <button onClick={handleGenerateReport} className="text-xs bg-blue-100 text-blue-700 font-bold px-4 py-2 rounded-lg hover:bg-blue-200 transition uppercase tracking-wider">
                                Regenerate Report
                              </button>
                            )}
                            {scanDetails?.status === 'completed' && (
                              <button onClick={handleDownloadPDF} className="text-xs bg-slate-800 text-white font-bold px-4 py-2 rounded-lg hover:bg-slate-700 transition shadow border border-slate-700 uppercase tracking-wider">
                                Export PDF
                              </button>
                            )}
                            {/* FIX: Render "Purge Scan" button in the action bar, visible ONLY to ADMINs */}
                            {user?.role === 'ADMIN' && (
                              <button onClick={handleDeleteScan} className="text-xs bg-red-100 text-red-700 border border-red-200 font-bold px-4 py-2 rounded-lg hover:bg-red-200 transition uppercase tracking-wider">
                                Delete Scan
                              </button>
                            )}
                          </div>
                        </div>

                        {activeScan.status === 'analyzing' || generatingReport ? (
                          <div className="flex items-center justify-center gap-4 bg-purple-50 p-8 rounded-xl border border-purple-200 shadow-inner">
                            <div className="animate-spin h-6 w-6 border-4 border-purple-600 border-t-transparent rounded-full"></div>
                            <span className="font-bold text-purple-800">AI is currently analyzing vulnerabilities...</span>
                          </div>
                        ) : scanDetails?.executive_summary ? (
                          scanDetails.executive_summary.includes("Error:") ? (
                             <div className="bg-red-50 p-6 rounded-xl border border-red-200 text-red-800 font-bold text-sm">
                                ⚠️ AI Generation Failed: {scanDetails.executive_summary}
                             </div>
                          ) : (
                            <div className="prose prose-sm max-w-none text-slate-800 bg-slate-50 p-6 rounded-xl border border-slate-200 shadow-inner">
                              <ReactMarkdown>{scanDetails.executive_summary}</ReactMarkdown>
                            </div>
                          )
                        ) : (
                          <p className="text-sm text-slate-500 italic bg-slate-50 p-4 rounded border border-slate-200">No report generated. AI may have timed out.</p>
                        )}
                      </div>
                    </div>
                  )}

                  {/* FINDINGS TAB */}
                  {activeTab === 'findings' && (
                    <div className="space-y-4">
                      <div className="flex gap-4 p-4 bg-slate-50 border border-slate-200 rounded-xl mb-6 shadow-sm">
                        <input type="text" placeholder="Search CWE or Title..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
                          className="flex-1 text-sm p-3 border border-slate-300 rounded-lg outline-none focus:border-blue-500 font-medium" />
                        <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)} className="text-sm p-3 border border-slate-300 rounded-lg bg-white outline-none font-bold text-slate-700">
                          <option value="ALL">All Severities</option>
                          <option value="CRITICAL">Critical</option>
                          <option value="HIGH">High</option>
                          <option value="MEDIUM">Medium</option>
                          <option value="LOW">Low</option>
                        </select>
                        <select value={filterScanner} onChange={e => setFilterScanner(e.target.value)} className="text-sm p-3 border border-slate-300 rounded-lg bg-white outline-none font-bold text-slate-700">
                          <option value="ALL">All Sources</option>
                          <option value="SAST">SAST</option>
                          <option value="SCA">SCA</option>
                          <option value="DAST">DAST</option>
                        </select>
                      </div>

                      {(filteredIssues || []).length === 0 && <p className="text-center text-slate-500 py-10 font-bold text-lg bg-slate-50 rounded-xl border border-slate-200">No findings match your filters.</p>}

                      {(filteredIssues || []).map(issue => {
                        if (!issue) return null;
                        return (
                        <div key={issue.id} onClick={() => setSelectedIssue(issue)} className="p-5 border border-slate-200 rounded-xl hover:border-blue-500 cursor-pointer hover:shadow-lg transition bg-white flex justify-between items-center group">
                          <div>
                            <div className="flex items-center gap-2 mb-2">
                              <span className={`text-xs font-black px-2.5 py-0.5 rounded border ${SEV_STYLES[issue.primary_severity] || 'bg-slate-100 text-slate-800'}`}>
                                {issue.primary_severity}
                              </span>
                              <span className="text-xs font-bold text-slate-500 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">{issue.cwe || 'No CWE'}</span>
                              {issue.status === 'remediated' && <span className="text-xs font-black bg-green-100 text-green-800 px-2 py-0.5 rounded border border-green-300">✓ REMEDIATED</span>}
                            </div>
                            <h4 className="font-black text-slate-900 text-lg group-hover:text-blue-700 transition">{issue.title}</h4>
                            <div className="flex gap-2 mt-3">
                              {/* HARDENING: Null-pointer check on findings.map and secure Set iterator to prevent white-screen crashes */}
                              {[...new Set((issue.findings || []).map(f => f ? f.scanner_type : ''))].filter(Boolean).map(type => (
                                <span key={type} className="text-[10px] font-bold bg-slate-100 border border-slate-200 text-slate-700 px-2 py-1 rounded uppercase tracking-wider">{type}</span>
                              ))}
                            </div>
                          </div>
                          <div className="text-blue-600 opacity-0 group-hover:opacity-100 group-hover:translate-x-1 transition font-black text-sm uppercase tracking-widest bg-blue-50 px-4 py-2 rounded-lg">Inspect →</div>
                        </div>
                      )})}
                    </div>
                  )}

                  {/* VULN MANAGEMENT TAB */}
                  {activeTab === 'vuln management' && (
                    <div className="p-8 bg-white rounded-xl border border-slate-200">
                      <div className="mb-8">
                        <h3 className="text-2xl font-black text-slate-900 tracking-tight">Correlation Traces & Workflow</h3>
                        <p className="text-sm text-slate-500 font-medium mt-1">Check off remediated items and assign responsibilities to your team.</p>
                      </div>

                      {(issues || []).length === 0 && <p className="text-slate-500 font-bold italic">No vulnerabilities to manage.</p>}

                      <div className="space-y-8 pl-4 border-l-4 border-slate-100">
                        {(issues || []).map(issue => {
                          if (!issue) return null;
                          return (
                          <div key={issue.id} className="relative pl-8 border-l-[3px] border-slate-200 pb-4 last:pb-0 last:border-transparent">
                            
                            <div className={`absolute -left-[13px] top-0 w-6 h-6 rounded-full ring-4 ring-white shadow-md flex items-center justify-center ${
                              issue.status === 'remediated' ? 'bg-green-500' :
                              ['CRITICAL', 'HIGH'].includes(issue.primary_severity) ? 'bg-red-500' :
                              issue.primary_severity === 'MEDIUM' ? 'bg-orange-500' : 'bg-blue-500'
                            }`}>
                              <div className="w-2 h-2 bg-white rounded-full"></div>
                            </div>

                            <div className={`border rounded-xl p-5 mb-4 shadow-sm transition ${issue.status === 'remediated' ? 'bg-green-50 border-green-200 opacity-75' : 'bg-slate-50 border-slate-200 hover:shadow-md'}`}>
                              <div className="flex justify-between items-start">
                                <div>
                                  <div className="flex items-center gap-3 mb-2">
                                    <span className={`text-xs font-black px-2.5 py-0.5 rounded uppercase tracking-wider border ${SEV_STYLES[issue.primary_severity] || 'bg-slate-100 text-slate-800'}`}>
                                      {issue.primary_severity}
                                    </span>
                                    {issue.owasp && <span className="text-xs font-bold text-blue-800 bg-blue-100 px-2.5 py-0.5 rounded border border-blue-200">{issue.owasp}</span>}
                                  </div>
                                  <h4 className="font-bold text-slate-900 text-lg">{issue.title}</h4>
                                </div>
                                
                                <div className="flex flex-col items-end gap-3">
                                  <label className="flex items-center gap-2 cursor-pointer text-sm font-bold text-slate-700 hover:text-green-700 transition">
                                    <input 
                                      type="checkbox" 
                                      className="w-5 h-5 cursor-pointer accent-green-600 rounded" 
                                      checked={issue.status === 'remediated'}
                                      onChange={(e) => updateIssueWorkflow(issue.id, { status: e.target.checked ? 'remediated' : 'open' })}
                                    />
                                    Mark Remediated
                                  </label>
                                  <div className="flex items-center gap-2 bg-white px-2 py-1 rounded border border-slate-300">
                                    <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Assignee:</span>
                                    <input 
                                      type="text" 
                                      value={issue.assignee || ''} 
                                      onChange={(e) => updateIssueWorkflow(issue.id, { assignee: e.target.value })}
                                      className="text-sm border-none outline-none text-slate-800 font-bold w-32 bg-transparent"
                                      placeholder="Unassigned"
                                      onBlur={(e) => updateIssueWorkflow(issue.id, { assignee: e.target.value })}
                                    />
                                  </div>
                                  <button onClick={() => setSelectedIssue(issue)} className="text-xs bg-blue-100 text-blue-700 hover:bg-blue-600 hover:text-white px-4 py-2 rounded-lg font-black uppercase tracking-wider transition shadow-sm">
                                    Inspect Issue / RAG →
                                  </button>
                                </div>
                              </div>
                            </div>

                            <div className="space-y-4 pl-6 relative">
                              {(issue.findings || []).map((f, index) => {
                                if (!f) return null;
                                return (
                                <div key={f.id} className="relative pl-6">
                                  <div className="absolute left-0 top-1/2 -mt-px w-6 h-px bg-slate-300"></div>
                                  <div className={`absolute left-0 top-0 w-px bg-slate-300 ${index === (issue.findings || []).length - 1 ? 'h-1/2' : 'h-full'}`}></div>
                                  
                                  <div className="bg-white border border-slate-200 rounded-lg p-4 text-sm flex items-center gap-4 shadow-sm hover:border-blue-300 transition">
                                    <span className={`text-[10px] font-black uppercase px-2 py-1 rounded tracking-widest ${
                                      f.scanner_type === 'SAST' ? 'bg-blue-100 text-blue-700 border border-blue-200' :
                                      f.scanner_type === 'SCA' ? 'bg-purple-100 text-purple-700 border border-purple-200' :
                                      'bg-emerald-100 text-emerald-700 border border-emerald-200'
                                    }`}>{f.scanner_type}</span>
                                    <div className="font-mono text-slate-700 text-xs break-all">
                                      {f.evidence?.file ? <span>File: <span className="text-slate-900 font-bold bg-slate-100 px-1 rounded">{f.evidence.file}</span> (Line {f.evidence.line || '?'})</span> : 
                                       f.evidence?.url ? <span>URL: <span className="text-slate-900 font-bold bg-slate-100 px-1 rounded">{f.evidence.url}</span> ({f.evidence.method})</span> : 
                                       f.evidence?.package ? <span>Pkg: <span className="text-slate-900 font-bold bg-slate-100 px-1 rounded">{f.evidence.package}</span> (v{f.evidence.installed_version})</span> : 'Unknown'}
                                    </div>
                                  </div>
                                </div>
                              )})}
                            </div>

                          </div>
                        )})}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Detail Drawer Side Pane */}
      {selectedIssue && (
        <div className="w-1/3 bg-white border-l border-slate-300 shadow-2xl z-10 shrink-0 h-screen sticky top-0 overflow-hidden">
          <DetailDrawer finding={selectedIssue} onClose={() => setSelectedIssue(null)} onUpdate={(id, insight) => {
             setIssues(prev => (prev || []).map(iss => iss.id === id ? { ...iss, ai_insight: insight } : iss));
          }}/>
        </div>
      )}

      {/* Modal Overlay */}
      {showModal && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center z-50 p-6">
        {/* UPGRADED: Expanded width layout to prevent layout cramming */}
        <div className="bg-white rounded-2xl w-full max-w-2xl border border-slate-300 shadow-2xl overflow-hidden">
        <NewScanModal onUpload={handleUpload} onCancel={() => setShowModal(false)} />
        </div>
        </div>
      )}
    </div>
  );
}