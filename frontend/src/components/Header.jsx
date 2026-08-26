import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, RefreshCw, Radio } from 'lucide-react';

export default function Header({ systemStatus, wsConnected }) {
  const [timeStr, setTimeStr] = useState(new Date().toLocaleTimeString());

  useEffect(() => {
    const timer = setInterval(() => setTimeStr(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(timer);
  }, []);

  const getStatusBadge = () => {
    switch (systemStatus) {
      case 'ATTACK':
        return (
          <span className="badge badge-attack">
            <ShieldAlert size={14} /> ACTIVE THREAT DETECTED
          </span>
        );
      case 'RECOVERING':
        return (
          <span className="badge badge-recovering">
            <RefreshCw size={14} className="spin" /> AUTONOMOUS SELF-HEALING IN PROGRESS
          </span>
        );
      case 'PROTECTED':
      default:
        return (
          <span className="badge badge-protected">
            <ShieldCheck size={14} /> SYSTEM PROTECTED & HEALTHY
          </span>
        );
    }
  };

  return (
    <header className="dashboard-header">
      <div className="brand-title">
        <ShieldCheck size={28} style={{ color: 'var(--accent-cyan)' }} />
        <div>
          OneChance Security Ops
          <span style={{ fontSize: '0.75rem', display: 'block', color: 'var(--text-muted)', fontWeight: 500 }}>
            Smart India Hackathon 2026 • Problem DJS_26_SW_05
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
        {getStatusBadge()}

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          <Radio size={14} style={{ color: wsConnected ? 'var(--accent-green)' : 'var(--accent-red)' }} />
          <span>{wsConnected ? 'TELEMETRY LIVE' : 'CONNECTING...'}</span>
        </div>

        <div className="font-mono" style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          {timeStr}
        </div>
      </div>
    </header>
  );
}
