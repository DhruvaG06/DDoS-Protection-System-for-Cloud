import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, RefreshCw, Radio, Activity, Cpu } from 'lucide-react';

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
            <RefreshCw size={14} className="spin" /> AUTONOMOUS HEALING IN PROGRESS
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
        <div className="brand-logo-glow">
          <ShieldCheck size={26} style={{ color: 'var(--accent-cyan)' }} />
        </div>
        <div>
          <div className="brand-name">
            OneChance <span className="brand-badge">PRO</span>
          </div>
          <span className="brand-subtitle">
            Autonomous Cloud DDoS Protection & Workload Self-Healing
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
        {getStatusBadge()}

        <div className="telemetry-pill">
          <Radio size={13} style={{ color: wsConnected ? 'var(--accent-green)' : 'var(--accent-red)' }} />
          <span>{wsConnected ? 'TELEMETRY LIVE' : 'CONNECTING...'}</span>
        </div>

        <div className="clock-pill font-mono">
          <Activity size={13} style={{ color: 'var(--accent-cyan)' }} />
          <span>{timeStr}</span>
        </div>
      </div>
    </header>
  );
}
