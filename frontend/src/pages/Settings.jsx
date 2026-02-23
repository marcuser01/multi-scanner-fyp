import React, { useState, useEffect } from 'react';
import axios from 'axios';

const Settings = () => {
  const [apiKey, setApiKey] = useState('');
  const [status, setStatus] = useState('');

  const saveKey = async () => {
    try {
      await axios.post('http://localhost:8000/api/settings/api-key', { key: apiKey });
      setStatus('Key saved successfully!');
    } catch (err) {
      setStatus('Error saving key.');
    }
  };

  return (
    <div className="max-w-2xl">
      <h1 className="text-2xl font-bold mb-6">Settings</h1>
      <div className="bg-white p-6 rounded-lg shadow-sm border">
        <label className="block text-sm font-medium mb-2">OpenRouter API Key</label>
        <input 
          type="password" 
          value={apiKey} 
          onChange={(e) => setApiKey(e.target.value)}
          className="w-full p-2 border rounded mb-4"
          placeholder="sk-or-v1-..."
        />
        <button onClick={saveKey} className="bg-blue-600 text-white px-4 py-2 rounded">
          Save Key
        </button>
        {status && <p className="mt-4 text-sm text-blue-600">{status}</p>}
      </div>
    </div>
  );
};

export default Settings;