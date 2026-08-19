import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Shield, Lock, User, Terminal, AlertTriangle } from 'lucide-react';
import { useAuth } from '../auth/auth-context';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { Alert } from '../components/feedback/Alert';
import { apiClient } from '../api/client';
import type { AuthResponse } from '../auth/auth-types';
import { ApiError } from '../api/errors';

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();
  
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const from = location.state?.from?.pathname || '/';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);

    try {
      const formData = new URLSearchParams();
      formData.append('username', username);
      formData.append('password', password);

      const response = await apiClient<AuthResponse>('/api/v1/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: formData.toString()
      });
      
      await login(response.access_token);
      navigate(from, { replace: true });
    } catch (err: any) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Unable to reach authentication service. Please check your credentials.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="relative flex h-screen w-full items-center justify-center bg-[#07090E] text-primary overflow-hidden">
      {/* PAGE BACKGROUND: Extremely low-opacity technical grid and subtle radial glow */}
      <div className="absolute inset-0 z-0 pointer-events-none">
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#ffffff03_1px,transparent_1px),linear-gradient(to_bottom,#ffffff03_1px,transparent_1px)] bg-[size:40px_40px]"></div>
        <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 h-[600px] w-[600px] rounded-full bg-blue-500/5 blur-[100px]"></div>
      </div>

      {/* Main container: 420-460px desktop width */}
      <div className="z-10 w-full max-w-[440px] px-4 md:px-0 flex flex-col">
        
        {/* BRAND AREA */}
        <div className="mb-8 flex flex-col items-center justify-center space-y-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-blue-500/20 bg-blue-500/10 shadow-[0_0_15px_rgba(59,130,246,0.15)]">
            <Shield className="h-6 w-6 text-cyan-400 drop-shadow-[0_0_5px_rgba(34,211,238,0.5)]" />
          </div>
          <div className="text-center">
            <h1 className="text-[32px] font-semibold tracking-tight text-white/95">NetSleuth AI</h1>
            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-white/40 mt-1">Forensic Intelligence</p>
          </div>
        </div>

        {/* AUTHENTICATION CARD */}
        <Card className="border border-white/5 bg-[#0F111A] shadow-lg shadow-black/40 rounded-2xl p-[32px]">
          
          {/* CARD HEADER */}
          <CardHeader className="p-0 pb-6">
            <CardTitle className="flex items-center gap-2 text-[13px] font-semibold tracking-wider text-white/70 uppercase">
              <Terminal className="h-4 w-4 text-cyan-400" />
              Secure Authentication
            </CardTitle>
          </CardHeader>
          
          <CardContent className="p-0">
            <form onSubmit={handleSubmit} className="space-y-6">
              
              {/* ERROR STATE */}
              {error && (
                <Alert variant="error" className="py-3 px-4 border border-rose-500/30 bg-[#2A0E13] text-rose-200 rounded-lg flex items-start gap-2 text-sm">
                  <AlertTriangle className="h-4 w-4 text-rose-500 flex-shrink-0 mt-0.5" />
                  <span>{error}</span>
                </Alert>
              )}
              
              {/* FORM LABELS & INPUTS: Investigator ID */}
              <div className="space-y-2 group">
                <label className="text-[11px] font-semibold uppercase tracking-wider text-white/50">
                  Investigator ID
                </label>
                <div className="relative">
                  <User className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-white/30" />
                  <Input 
                    type="text" 
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    placeholder="Enter ID or username" 
                    className="h-[54px] pl-12 rounded-[10px] border-white/10 bg-[#07090E] text-white placeholder:text-white/20 focus-visible:border-cyan-500/60 focus-visible:ring-1 focus-visible:ring-cyan-500/20 transition-all shadow-inner shadow-black/20"
                    required 
                  />
                </div>
              </div>
              
              {/* FORM LABELS & INPUTS: Passphrase */}
              <div className="space-y-2 group">
                <div className="flex items-center justify-between">
                  <label className="text-[11px] font-semibold uppercase tracking-wider text-white/50">
                    Passphrase
                  </label>
                </div>
                <div className="relative">
                  <Lock className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-white/30" />
                  <Input 
                    type="password" 
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    placeholder="••••••••••••" 
                    className="h-[54px] pl-12 rounded-[10px] border-white/10 bg-[#07090E] text-white placeholder:text-white/20 focus-visible:border-cyan-500/60 focus-visible:ring-1 focus-visible:ring-cyan-500/20 transition-all font-mono text-lg tracking-widest shadow-inner shadow-black/20"
                    required 
                  />
                </div>
              </div>
              
              {/* PRIMARY BUTTON */}
              <div className="pt-2">
                <Button 
                  type="submit" 
                  className="h-[54px] w-full rounded-[10px] bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 border-none text-white font-semibold text-sm shadow-[0_0_15px_rgba(8,145,178,0.15)] hover:shadow-[0_0_20px_rgba(8,145,178,0.25)] transition-all disabled:opacity-70 disabled:cursor-not-allowed" 
                  disabled={isSubmitting}
                >
                  <span className="flex items-center justify-center gap-2">
                    {isSubmitting ? (
                      <>
                        <div className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white"></div>
                        Authenticating...
                      </>
                    ) : (
                      'Initiate Session'
                    )}
                  </span>
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
        
        {/* SECURITY STATUS */}
        <div className="mt-8 flex items-center justify-center gap-2 text-[11px] font-medium tracking-widest text-white/30 uppercase">
          <span className="h-1.5 w-1.5 rounded-full bg-white/20"></span>
          Authorized Access Only
        </div>
      </div>
    </div>
  );
}
