import React, { useState, useContext } from 'react';
import axios from 'axios';
import { AuthContext } from '../App';

export default function Settings() {
  const { user } = useContext(AuthContext);
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [pwdMsg, setPwdMsg] = useState('');
  
  const [apiKey, setApiKey] = useState('');
  const [keyMsg, setKeyMsg] = useState('');

  const changePassword = async (e) => {
    e.preventDefault();
    try {
      await axios.post('/api/auth/change-password', { old_password: oldPassword, new_password: newPassword });
      setPwdMsg("Password changed successfully!");
      setOldPassword(''); setNewPassword('');
    } catch (err) { setPwdMsg(err.response?.data?.detail || "Error changing password."); }
  };

  const saveVaultKey = async (e) => {
    e.preventDefault();
    try {
      await axios.post('/api/settings/llm-key', { key: apiKey });
      setKeyMsg("API Key securely encrypted and vaulted!");
      setApiKey('');
    } catch (err) { setKeyMsg("Error saving API Key."); }
  };

  return (
    <div className="p-10 max-w-4xl">
      <h1 className="text-3xl font-black text-slate-900 mb-8">Platform Settings</h1>
      
      {/* Profile Settings (All Users) */}
      <div className="bg-white p-8 rounded-2xl shadow-sm border border-slate-200 mb-8">
        <h2 className="text-lg font-bold text-slate-800 mb-6">Security Profile</h2>
        <form onSubmit={changePassword} className="space-y-4 max-w-md">
          <input type="password" placeholder="Current Password" value={oldPassword} onChange={e=>setOldPassword(e.target.value)} className="w-full p-3 border rounded-xl bg-slate-50 text-sm" required/>
          <input type="password" placeholder="New Password" value={newPassword} onChange={e=>setNewPassword(e.target.value)} className="w-full p-3 border rounded-xl bg-slate-50 text-sm" required/>
          <button className="bg-slate-800 text-white font-bold px-6 py-3 rounded-xl text-sm hover:bg-slate-700">Update Password</button>
          {pwdMsg && <p className="text-xs font-bold mt-2 text-blue-600">{pwdMsg}</p>}
        </form>
      </div>

      {/* Admin Settings */}
      {user.role === 'ADMIN' && (
        <div className="bg-purple-50 p-8 rounded-2xl shadow-sm border border-purple-200">
          <div className="mb-6">
            <span className="bg-purple-600 text-white text-[10px] font-black px-2 py-1 rounded uppercase tracking-widest">Admin Only</span>
            <h2 className="text-lg font-bold text-purple-900 mt-2">AI Integrations Vault</h2>
            <p className="text-xs text-purple-700 mt-1">OpenRouter API keys are encrypted at rest using AES-256 (Fernet).</p>
          </div>
          <form onSubmit={saveVaultKey} className="space-y-4 max-w-md">
            <input type="password" placeholder="sk-or-v1-..." value={apiKey} onChange={e=>setApiKey(e.target.value)} className="w-full p-3 border border-purple-300 rounded-xl bg-white text-sm" required/>
            <button className="bg-purple-700 text-white font-bold px-6 py-3 rounded-xl text-sm hover:bg-purple-800">Vault API Key</button>
            {keyMsg && <p className="text-xs font-bold mt-2 text-purple-800">{keyMsg}</p>}
          </form>
        </div>
      )}
    </div>
  );
}