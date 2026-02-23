import React, { useState, useEffect } from 'react';
import axios from 'axios';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

export const DetailDrawer = ({ finding, onClose, onUpdate }) => {
  const [aiInsight, setAiInsight] = useState(finding.ai_insight);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setAiInsight(finding.ai_insight);
  }, [finding]);

  const getAIAnalysis = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`http://localhost:8000/api/results/${finding.id}/ai-triage`);
      const insight = res.data.insight;
      setAiInsight(insight);
      if (onUpdate) onUpdate(finding.id, insight);
    } catch (err) {
      setAiInsight("Error: Failed to reach AI service.");
    }
    setLoading(false);
  };

  return (
    /* Main Container Fix: 
       - 'fixed right-0 top-0': Anchors it to the side regardless of page scroll.
       - 'h-screen': Forces it to fill the full height of the viewport.
       - 'w-[460px]': Adjusted width to be slightly shorter as requested.
    */
    <div className="fixed right-0 top-0 flex flex-col h-screen w-[460px] bg-white shadow-2xl rounded-l-3xl overflow-hidden border-l border-slate-200 z-50">
      
      {/* Sticky Header: Always visible */}
      <div className="flex justify-between items-center p-6 border-b bg-white/80 backdrop-blur-md z-10">
        <button 
          onClick={onClose} 
          className="flex items-center gap-2 text-slate-500 hover:text-slate-800 transition-colors font-semibold text-sm"
        >
          <span className="text-lg">✕</span> Close
        </button>
        <span className={`text-[10px] px-3 py-1 rounded-full font-bold uppercase tracking-wider ${
          finding.severity === 'HIGH' ? 'bg-red-100 text-red-700' : 'bg-orange-100 text-orange-700'
        }`}>
          {finding.severity} Severity
        </span>
      </div>

      {/* Scrollable Content Area */}
      <div className="flex-1 overflow-y-auto p-8 custom-scrollbar">
        <h2 className="text-2xl font-extrabold text-slate-800 mb-6 leading-tight">
          {finding.title}
        </h2>
        
        {/* Comprehensive Metadata Grid */}
        <div className="grid grid-cols-2 gap-3 mb-10">
          <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100">
            <p className="text-[10px] font-black text-slate-400 uppercase mb-1">CWE Classification</p>
            <p className="text-sm font-bold text-slate-700">{finding.cwe || "N/A"}</p>
          </div>
          <div className="bg-slate-50 p-4 rounded-2xl border border-slate-100">
            <p className="text-[10px] font-black text-slate-400 uppercase mb-1">OWASP Classification</p>
            <p className="text-sm font-bold text-slate-700">{finding.owasp_full || "General"}</p>
          </div>
          <div className="col-span-2 bg-slate-900 p-4 rounded-2xl shadow-inner">
            <p className="text-[10px] font-black text-indigo-300 uppercase mb-2">Vulnerable Location</p>
            <p className="text-xs font-mono text-indigo-50 break-all bg-white/10 p-2 rounded">
              {finding.file_path} <span className="text-indigo-400">: Line {finding.line_number}</span>
            </p>
          </div>
        </div>

        {/* AI Section */}
        <div className="space-y-6">
          <div className="flex items-center gap-3">
            <div className="h-px flex-1 bg-slate-200"></div>
            <h3 className="text-[10px] font-black text-indigo-500 uppercase tracking-[0.2em]">AI Security Insights</h3>
            <div className="h-px flex-1 bg-slate-200"></div>
          </div>

          {!aiInsight ? (
            <button 
              onClick={getAIAnalysis}
              disabled={loading}
              className="w-full group relative flex items-center justify-center gap-3 bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-5 rounded-2xl transition-all shadow-lg hover:shadow-indigo-200 disabled:bg-slate-100 disabled:text-slate-400"
            >
              {loading ? (
                <span className="animate-pulse">Analyzing Codebase...</span>
              ) : (
                <>
                  <span>Generate Triage Report</span>
                  <span className="group-hover:translate-x-1 transition-transform">→</span>
                </>
              )}
            </button>
          ) : (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
              <div className="prose prose-slate prose-sm max-w-none">
                <ReactMarkdown 
                  remarkPlugins={[remarkGfm]}
                  components={{
                    code({ node, inline, className, children, ...props }) {
                      const match = /language-(\w+)/.exec(className || '');
                      return !inline ? (
                        <div className="my-6 rounded-xl overflow-hidden border border-slate-200 shadow-sm">
                          <div className="bg-slate-100 px-4 py-2 text-[10px] text-slate-500 font-bold border-b flex justify-between">
                            <span>{match ? match[1].toUpperCase() : 'CODE BLOCK'}</span>
                            <span className="text-indigo-500">Suggested Fix</span>
                          </div>
                          <pre className="bg-slate-50 p-5 m-0 overflow-x-auto">
                            <code className="text-slate-800 font-mono text-xs leading-relaxed" {...props}>
                              {children}
                            </code>
                          </pre>
                        </div>
                      ) : (
                        <code className="bg-indigo-50 text-indigo-700 px-1.5 py-0.5 rounded-md font-bold text-xs border border-indigo-100" {...props}>
                          {children}
                        </code>
                      );
                    },
                    ul: ({children}) => <ul className="list-disc pl-4 space-y-1 mb-4">{children}</ul>,
                    p: ({children}) => <p className="text-slate-600 leading-relaxed mb-4">{children}</p>
                  }}
                >
                  {aiInsight}
                </ReactMarkdown>
              </div>

              <button 
                onClick={() => setAiInsight(null)} 
                className="mt-8 w-full py-3 text-[10px] font-bold text-slate-400 uppercase tracking-widest hover:text-indigo-600 transition-colors border border-dashed border-slate-200 rounded-xl"
              >
                ↻ Refresh Analysis
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};