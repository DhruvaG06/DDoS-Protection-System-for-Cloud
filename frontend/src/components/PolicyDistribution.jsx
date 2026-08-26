import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

export default function PolicyDistribution({ policyCounts }) {
  const total = (policyCounts.ALLOW || 0) + (policyCounts.CHALLENGE || 0) + (policyCounts.BLOCK || 0) || 1;
  const allowPct = (((policyCounts.ALLOW || 0) / total) * 100).toFixed(0);
  const challengePct = (((policyCounts.CHALLENGE || 0) / total) * 100).toFixed(0);
  const blockPct = (((policyCounts.BLOCK || 0) / total) * 100).toFixed(0);

  return (
    <div className="cyber-card">
      <div className="card-title">
        <span>Adaptive Policy Decisions</span>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Action Distribution</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.75rem', textAlign: 'center', margin: '0.5rem 0' }}>
        <div style={{ background: 'rgba(0, 230, 118, 0.08)', padding: '0.75rem', borderRadius: '8px', border: '1px solid rgba(0, 230, 118, 0.2)' }}>
          <ShieldCheck size={18} style={{ color: 'var(--accent-green)', marginBottom: '0.2rem' }} />
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>ALLOW</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--accent-green)' }}>{policyCounts.ALLOW || 0}</div>
        </div>

        <div style={{ background: 'rgba(255, 234, 0, 0.08)', padding: '0.75rem', borderRadius: '8px', border: '1px solid rgba(255, 234, 0, 0.2)' }}>
          <AlertTriangle size={18} style={{ color: 'var(--accent-yellow)', marginBottom: '0.2rem' }} />
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>CHALLENGE</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--accent-yellow)' }}>{policyCounts.CHALLENGE || 0}</div>
        </div>

        <div style={{ background: 'rgba(255, 23, 68, 0.08)', padding: '0.75rem', borderRadius: '8px', border: '1px solid rgba(255, 23, 68, 0.2)' }}>
          <ShieldAlert size={18} style={{ color: 'var(--accent-red)', marginBottom: '0.2rem' }} />
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>BLOCK</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--accent-red)' }}>{policyCounts.BLOCK || 0}</div>
        </div>
      </div>

      <div style={{ display: 'flex', height: '8px', borderRadius: '4px', overflow: 'hidden', marginTop: '0.75rem' }}>
        <div style={{ width: `${allowPct}%`, background: 'var(--accent-green)' }} />
        <div style={{ width: `${challengePct}%`, background: 'var(--accent-yellow)' }} />
        <div style={{ width: `${blockPct}%`, background: 'var(--accent-red)' }} />
      </div>
    </div>
  );
}
