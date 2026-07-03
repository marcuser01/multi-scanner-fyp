import React, { useState, useEffect, createContext, useContext } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link, useNavigate, useLocation } from 'react-router-dom';
import axios from 'axios';
import Dashboard from './pages/Dashboard';
import Settings from './pages/Settings';
import UserManagement from './pages/UserManagement';
import AuditLogs from './pages/AuditLogs';

axios.defaults.withCredentials = true;
export const AuthContext = createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isFirstRun, setIsFirstRun] = useState(false);

  useEffect(() => { checkSession(); }, []);

  const checkSession = async () => {
    try {
      const res = await axios.get('/api/auth/me');
      setUser(res.data);
    } catch (err) {
      setUser(null);
      // If unauthorized, check if the system is completely empty
      try {
        const stat = await axios.get('/api/auth/system-status');
        setIsFirstRun(!stat.data.is_setup);
      } catch (e) { setIsFirstRun(false); }
    } finally { setLoading(false); }
  };

  const login = async (username, password) => {
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);
    await axios.post('/api/auth/login', formData);
    await checkSession();
  };

  const register = async (username, password) => {
    await axios.post('/api/auth/register', { username, password });
    await login(username, password);
  };

  const logout = async () => {
    await axios.post('/api/auth/logout');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, register, logout, loading, isFirstRun }}>
      {!loading && children}
    </AuthContext.Provider>
  );
};

// --- HARDEST-LEVEL ROUTE ENFORCEMENT ---

const ProtectedRoute = ({ children, requireAdmin = false }) => {
  const { user, logout } = useContext(AuthContext);
  const location = useLocation();
  
  // 1. Enforce Authentication Guard
  if (!user) return <Navigate to="/login" state={{ from: location }} replace />;

  // 2. Enforce Role Authorization Guard (Prevents direct URL manipulation privilege bypass)
  if (requireAdmin && user.role !== 'ADMIN') {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="flex min-h-screen bg-slate-100">
      <nav className="w-64 bg-slate-900 text-white p-6 shrink-0 flex flex-col z-20 shadow-xl">
        <div className="mb-12">
          <h1 className="text-sm font-black uppercase tracking-widest text-slate-400">Security</h1>
          <p className="text-2xl font-black text-blue-400">Riskwise</p>
        </div>
        <div className="space-y-2 flex-1">
          <Link to="/" className="block py-3 px-4 rounded-lg font-bold text-sm text-slate-300 hover:bg-slate-800 hover:text-white transition">Dashboard</Link>
          <Link to="/settings" className="block py-3 px-4 rounded-lg font-bold text-sm text-slate-300 hover:bg-slate-800 hover:text-white transition">Settings</Link>
          
          {user.role === 'ADMIN' && (
            <>
              <Link to="/users" className="block py-3 px-4 rounded-lg font-bold text-sm text-slate-300 hover:bg-slate-800 hover:text-white transition">Team Management</Link>
              <Link to="/logs" className="block py-3 px-4 rounded-lg font-bold text-sm text-slate-300 hover:bg-slate-800 hover:text-white transition">System Logs</Link>
            </>
          )}
        </div>
        <div className="pt-6 border-t border-slate-700">
          <div className="mb-4">
            <p className="text-[10px] font-black uppercase tracking-widest text-slate-500">Logged in as</p>
            <p className="text-sm font-bold text-white">{user.username} <span className="text-[9px] bg-blue-600 px-1.5 py-0.5 rounded ml-1">{user.role}</span></p>
          </div>
          <button onClick={logout} className="w-full text-left text-xs font-bold text-red-400 hover:text-red-300 uppercase tracking-widest transition">Log Out →</button>
        </div>
      </nav>
      <main className="flex-1 overflow-y-auto">{children}</main>
    </div>
  );
};

// --- ELEGANT CATCH-ALL 404 COMPONENT ---

const NotFound = () => {
  const { user, isFirstRun } = useContext(AuthContext);

  // If unauthenticated, redirect to correct starting workflows cleanly
  if (!user) {
    if (isFirstRun) return <Navigate to="/register" replace />;
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-[80vh] text-center p-8 bg-slate-100">
      <span className="text-7xl mb-4">🔍</span>
      <h2 className="text-3xl font-black text-slate-900 mb-2">Page Not Found</h2>
      <p className="text-sm text-slate-500 max-w-sm mb-6 font-semibold leading-relaxed">
        The resource or view you are trying to access does not exist or has been restricted by administrators.
      </p>
      <Link to="/" className="bg-blue-600 hover:bg-blue-700 text-white font-bold px-6 py-3 rounded-xl shadow-lg transition uppercase text-xs tracking-wider">
        Return to Dashboard
      </Link>
    </div>
  );
};

const AuthScreen = ({ mode }) => {
  const { login, register, isFirstRun } = useContext(AuthContext);
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  useEffect(() => { if (isFirstRun && mode === 'login') navigate('/register'); }, [isFirstRun, mode]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (mode === 'login') await login(username, password);
      else await register(username, password);
      navigate('/');
    } catch (err) { setError(err.response?.data?.detail || "Authentication failed"); }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100">
      <form onSubmit={handleSubmit} className="bg-white p-10 rounded-3xl shadow-xl w-96 border border-slate-200">
        <div className="mb-8 text-center">
          <p className="text-3xl font-black text-blue-600">Riskwise</p>
          <p className="text-xs font-bold text-slate-400 uppercase tracking-widest mt-1">
            {isFirstRun ? 'First Run Setup' : mode === 'login' ? 'Platform Login' : 'Account Creation'}
          </p>
        </div>
        
        {isFirstRun && <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-xl text-xs text-blue-800 font-medium leading-relaxed">Welcome! Since this is the first run, the account you create now will be granted full <b>ADMIN</b> privileges.</div>}
        {error && <div className="mb-4 text-xs font-bold text-red-600 bg-red-50 p-3 rounded-lg border border-red-200">{error}</div>}
        
        <input className="w-full p-4 mb-4 border border-slate-300 rounded-xl bg-slate-50 outline-none focus:border-blue-500 focus:bg-white transition text-sm font-medium" placeholder="Username" value={username} onChange={e=>setUsername(e.target.value)} required minLength={4}/>
        <input className="w-full p-4 mb-6 border border-slate-300 rounded-xl bg-slate-50 outline-none focus:border-blue-500 focus:bg-white transition text-sm font-medium" type="password" placeholder="Password" value={password} onChange={e=>setPassword(e.target.value)} required minLength={6}/>
        
        <button className="w-full bg-blue-600 text-white font-black uppercase tracking-wider py-4 rounded-xl hover:bg-blue-700 transition shadow-lg shadow-blue-500/30 text-sm">
          {mode === 'login' ? 'Sign In' : 'Create Account'}
        </button>
        
        {!isFirstRun && (
          <p className="mt-6 text-center text-sm text-slate-500 font-medium">
            {mode === 'login' ? "Don't have an account? " : "Already have an account? "}
            <Link to={mode === 'login' ? '/register' : '/login'} className="text-blue-600 font-bold hover:underline">
              {mode === 'login' ? 'Register' : 'Sign In'}
            </Link>
          </p>
        )}
      </form>
    </div>
  );
};

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<AuthScreen mode="login" />} />
          <Route path="/register" element={<AuthScreen mode="register" />} />
          
          {/* SECURE ROUTES: Wrapped with both Auth and explicit Role authorization checks */}
          <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
          <Route path="/users" element={<ProtectedRoute requireAdmin={true}><UserManagement /></ProtectedRoute>} />
          <Route path="/logs" element={<ProtectedRoute requireAdmin={true}><AuditLogs /></ProtectedRoute>} />
          
          {/* CATCH-ALL: Redirects unauthorized users and renders beautiful slate 404 for authorized ones */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}