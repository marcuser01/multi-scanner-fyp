import React, { useState, useEffect } from 'react';
import axios from 'axios';

export default function UserManagement() {
  const [users, setUsers] = useState([]);

  // Fetches current team listings
  const fetchUsers = async () => {
    try { 
      const res = await axios.get('/api/users'); 
      setUsers(res.data); 
    } catch (err) { 
      console.error(err); 
    }
  };

  useEffect(() => { 
    fetchUsers(); 
  }, []);

  // Updates user roles and assignment status
  const handleUpdate = async (id, role, isActive) => {
    try {
      await axios.patch(`/api/users/${id}`, { role, is_active: isActive });
      fetchUsers();
    } catch (err) { 
      alert(err.response?.data?.detail || "Update failed"); 
    }
  };

  // Permanently removes user profiles with safe-orphaning confirmations
  const handleDelete = async (id, username) => {
    if (!window.confirm(`Are you sure you want to permanently delete user "${username}"? All their scan metadata will be safely kept.`)) return;
    try {
      await axios.delete(`/api/users/${id}`);
      fetchUsers();
    } catch (err) { 
      alert(err.response?.data?.detail || "Remove user failed"); 
    }
  };

  return (
    <div className="p-10 max-w-6xl">
      <h1 className="text-3xl font-black text-slate-900 mb-8">Team Management</h1>
      <div className="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
        <table className="w-full text-left">
          <thead className="bg-slate-50 border-b border-slate-200">
            <tr>
              <th className="p-4 text-xs font-black text-slate-500 uppercase">User</th>
              <th className="p-4 text-xs font-black text-slate-500 uppercase">Role</th>
              <th className="p-4 text-xs font-black text-slate-500 uppercase">Status</th>
              <th className="p-4 text-xs font-black text-slate-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {users.map(u => (
              <tr key={u.id} className="hover:bg-slate-50">
                <td className="p-4 font-bold text-sm text-slate-800">{u.username}</td>
                <td className="p-4">
                  <select 
                    value={u.role} 
                    onChange={(e) => handleUpdate(u.id, e.target.value, u.is_active)} 
                    className="text-sm border rounded p-1 bg-white font-semibold"
                  >
                    <option value="DEVELOPER">Developer</option>
                    <option value="ANALYST">Analyst</option>
                    <option value="ADMIN">Admin</option>
                  </select>
                </td>
                <td className="p-4">
                  <select 
                    value={u.is_active} 
                    onChange={(e) => handleUpdate(u.id, u.role, e.target.value === 'true')} 
                    className="text-sm border rounded p-1 bg-white font-semibold"
                  >
                    <option value={true}>Active</option>
                    <option value={false}>Suspended</option>
                  </select>
                </td>
                <td className="p-4">
                  <button 
                    onClick={() => handleDelete(u.id, u.username)} 
                    className="text-xs bg-red-100 text-red-700 hover:bg-red-200 px-3 py-1.5 rounded-lg font-black transition"
                  >
                    REMOVE USER
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}