import React from 'react';
import { Server, CheckCircle2, AlertOctagon, RefreshCw } from 'lucide-react';

export default function InfrastructureHealth({ instances }) {
  const getStatusIcon = (status) => {
    switch (status) {
      case 'HEALTHY':
        return <CheckCircle2 size={16} style={{ color: 'var(--accent-green)' }} />;
      case 'UNHEALTHY':
      case 'ISOLATED':
        return <AlertOctagon size={16} style={{ color: 'var(--accent-red)' }} />;
      case 'RECOVERING':
        return <RefreshCw size={16} className="spin" style={{ color: 'var(--accent-yellow)' }} />;
      default:
        return <Server size={16} style={{ color: 'var(--text-muted)' }} />;
    }
  };

  return (
    <div className="cyber-card">
      <div className="card-title">
        <span>Infrastructure Cluster Health</span>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Target Services Pool</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem' }}>
        {instances && instances.length > 0 ? (
          instances.map((inst) => (
            <div
              key={inst.instance_id}
              style={{
                background: inst.status === 'HEALTHY' ? 'rgba(0, 230, 118, 0.05)' : inst.status === 'ISOLATED' ? 'rgba(255, 23, 68, 0.08)' : 'rgba(255, 234, 0, 0.05)',
                border: `1px solid ${inst.status === 'HEALTHY' ? 'rgba(0, 230, 118, 0.2)' : inst.status === 'ISOLATED' ? 'rgba(255, 23, 68, 0.3)' : 'rgba(255, 234, 0, 0.2)'}`,
                borderRadius: '8px',
                padding: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, fontSize: '0.9rem' }}>{inst.instance_id}</span>
                {getStatusIcon(inst.status)}
              </div>

              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
                Status: <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{inst.status}</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Traffic Pool: <span style={{ color: inst.is_accepting_traffic ? 'var(--accent-green)' : 'var(--accent-red)' }}>{inst.is_accepting_traffic ? 'ACTIVE' : 'ISOLATED'}</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between', marginTop: '0.2rem' }}>
                <span>Latency: {inst.average_latency_ms ? inst.average_latency_ms.toFixed(1) : 0}ms</span>
                <span>Errors: {inst.error_count || 0}</span>
              </div>
            </div>
          ))
        ) : (
          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', gridColumn: 'span 3', padding: '1rem', textAlign: 'center' }}>
            Connecting to cluster service registry...
          </div>
        )}
      </div>
    </div>
  );
}
