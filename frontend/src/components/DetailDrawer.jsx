import React, { useState, useEffect } from 'react';
import axios from 'axios';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

const SEV_COLORS = {
  CRITICAL: 'bg-red-100 text-red-800 border-red-300',
  HIGH: 'bg-orange-100 text-orange-800 border-orange-300',
  MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-300',
  LOW: 'bg-blue-100 text-blue-800 border-blue-300',
  INFO: 'bg-slate-100 text-slate-800 border-slate-300'
};

export const DetailDrawer = ({ finding: issue, onClose, onUpdate }) => {
  const [aiInsight, setAiInsight] = useState(issue.ai_insight);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setAiInsight(issue.ai_insight);
  }, [issue]);

  const getAIAnalysis = async () => {
    setLoading(true);
    try {
      // Hits backend triage which runs RAG and records to database
      const res = await axios.post(`/api/results/${issue.id}/ai-triage`);
      const insight = res.data.insight;
      
      setAiInsight(insight);
      // Cleanly pass state changes to parent view collections
      if (onUpdate) onUpdate(issue.id, insight);
    } catch (err) {
      setAiInsight("Error: Failed to reach AI service. Verify OpenRouter API key inside settings.");
    }
    setLoading(false);
  };

  return (
    <div className="flex flex-col h-full w-full bg-white relative">
      <div className="flex justify-between items-center p-6 border-b border-slate-200 bg-slate-50 shrink-0">
        <button onClick={onClose} className="text-slate-600 hover:text-slate-900 font-bold text-sm bg-slate-200 px-3 py-1.5 rounded-lg transition">
          ← Back
        </button>
        <span className={`text-xs px-3 py-1.5 rounded-full font-black uppercase border ${SEV_COLORS[issue.primary_severity] || SEV_COLORS.INFO}`}>
          {issue.primary_severity}
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-8 custom-scrollbar">
        <h2 className="text-xl font-black text-slate-900 mb-6 leading-snug">{issue.title}</h2>
        
        <div className="grid grid-cols-2 gap-3 mb-8">
          <div className="bg-slate-50 p-4 rounded-xl border border-slate-300">
            <p className="text-[10px] font-black text-slate-500 uppercase mb-1">CWE ID</p>
            <p className="text-sm font-bold text-slate-900">{issue.cwe || "N/A"}</p>
          </div>
          <div className="bg-slate-50 p-4 rounded-xl border border-slate-300">
            <p className="text-[10px] font-black text-slate-500 uppercase mb-1">OWASP Category</p>
            <p className="text-sm font-bold text-slate-900">{issue.owasp || "General"}</p>
          </div>
          <div className="col-span-2 bg-slate-900 p-4 rounded-xl border border-slate-700">
            <p className="text-[10px] font-black text-blue-400 uppercase mb-2 tracking-wider">Correlated Evidence</p>
            <div className="space-y-2 max-h-48 overflow-y-auto custom-scrollbar pr-2">
              {issue.findings?.map(f => (
                <div key={f.id} className="text-xs font-mono text-slate-300 bg-slate-800 p-2 rounded break-words">
                  <span className="text-blue-300 font-bold">[{f.scanner_type}]</span>{' '}
                  {f.evidence?.file ? `${f.evidence.file} : Line ${f.evidence.line || '?'}` : 
                   f.evidence?.url ? `${f.evidence.method || 'GET'} ${f.evidence.url}` : 
                   f.evidence?.package ? `Pkg: ${f.evidence.package} (v${f.evidence.installed_version})` : 'Unknown Location'}
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="flex items-center gap-3">
            <div className="h-px flex-1 bg-slate-300"></div>
            <h3 className="text-xs font-black text-blue-700 uppercase tracking-widest">AI Context & Remediation</h3>
            <div className="h-px flex-1 bg-slate-300"></div>
          </div>

          {!aiInsight ? (
            <button onClick={getAIAnalysis} disabled={loading} className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-4 rounded-2xl shadow-lg transition disabled:opacity-50 text-sm uppercase">
              {loading ? 'Analyzing Source & DB...' : 'Generate AI Report'}
            </button>
          ) : (
            <div className="animate-in fade-in duration-500">
              <div className="prose prose-slate prose-sm max-w-none mb-6">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{aiInsight}</ReactMarkdown>
              </div>
              <button onClick={getAIAnalysis} disabled={loading} className="w-full bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 font-bold py-3 rounded-xl transition disabled:opacity-50 text-xs uppercase">
                {loading ? 'Re-analyzing...' : '↻ Re-analyze with AI'}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};