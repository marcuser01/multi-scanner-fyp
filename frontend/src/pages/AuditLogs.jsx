import React, { useState, useEffect } from 'react';
import axios from 'axios';

export default function AuditLogs() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const res = await axios.get('/api/audit');
        setLogs(res.data);
      } catch (err) { console.error("Failed to fetch logs", err); }
    };
    fetchLogs();
  }, []);

  return (
    <div className="p-10 max-w-6xl">
      <h1 className="text-3xl font-black text-slate-900 mb-8">System Audit Logs</h1>
      <div className="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
        <table className="w-full text-left">
          <thead className="bg-slate-50 border-b border-slate-200">
            <tr>
              <th className="p-4 text-xs font-black text-slate-500 uppercase">Timestamp</th>
              <th className="p-4 text-xs font-black text-slate-500 uppercase">User</th>
              <th className="p-4 text-xs font-black text-slate-500 uppercase">Action</th>
              <th className="p-4 text-xs font-black text-slate-500 uppercase">Target Resource</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {logs.map(log => (
              <tr key={log.id} className="hover:bg-slate-50">
                <td className="p-4 text-xs text-slate-500 font-mono">{new Date(log.timestamp).toLocaleString()}</td>
                <td className="p-4 font-bold text-sm text-slate-800">{log.username}</td>
                <td className="p-4 text-sm font-medium text-slate-700">
                  <span className="bg-slate-100 border border-slate-200 px-2 py-1 rounded text-xs">{log.action}</span>
                </td>
                <td className="p-4 text-sm font-mono text-slate-600">{log.target || "N/A"}</td>
              </tr>
            ))}
            {logs.length === 0 && (
              <tr><td colSpan="4" className="p-8 text-center text-slate-500 font-bold">No audit logs recorded yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}