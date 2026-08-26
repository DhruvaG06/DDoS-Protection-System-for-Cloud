import React from 'react';
import { Search, HelpCircle, FileText } from 'lucide-react';

export default function DecisionInspector({ selectedEvent }) {
  if (!selectedEvent) {
    return (
      <div className="cyber-card">
        <div className="card-title">
          <span>Decision Explainability Inspector</span>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>AI Rationale</span>
        </div>
        <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
          <Search size={24} style={{ marginBottom: '0.5rem', opacity: 0.5 }} />
          <div>Select any event from the Live Stream to inspect the exact feature signals and ML probability breakdown.</div>
        </div>
      </div>
    );
  }

  const features = selectedEvent.features || {};
  const reasons = selectedEvent.reasons || [];

  return (
    <div className="cyber-card">
      <div className="card-title">
        <span>Decision Inspector: {selectedEvent.event_id || 'Event'}</span>
        <span className={`badge badge-${(selectedEvent.decision || 'ALLOW').toLowerCase()}`}>
          {selectedEvent.decision || 'ALLOW'}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.8rem', marginBottom: '1rem' }}>
        <div>
          <span style={{ color: 'var(--text-muted)' }}>Risk Score:</span>{' '}
          <strong style={{ color: selectedEvent.risk_score >= 70 ? 'var(--accent-red)' : 'var(--accent-green)' }}>
            {selectedEvent.risk_score ? selectedEvent.risk_score.toFixed(1) : 0}/100
          </strong>
        </div>
        <div>
          <span style={{ color: 'var(--text-muted)' }}>Threat Level:</span>{' '}
          <strong>{selectedEvent.threat_level || 'LOW'}</strong>
        </div>
        <div>
          <span style={{ color: 'var(--text-muted)' }}>Origin:</span>{' '}
          <span style={{ color: (selectedEvent.attack_origin || '').includes('INTERNAL') ? 'var(--accent-purple)' : 'var(--accent-blue)' }}>
            {selectedEvent.attack_origin || 'EXTERNAL'}
          </span>
        </div>
        <div>
          <span style={{ color: 'var(--text-muted)' }}>Client IP / Source:</span>{' '}
          <span className="font-mono">{selectedEvent.source || 'N/A'}</span>
        </div>
      </div>

      <div style={{ fontSize: '0.8rem', marginBottom: '0.5rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
        Explainability Signals & Reasons:
      </div>
      <ul style={{ paddingLeft: '1.2rem', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
        {reasons.length > 0 ? (
          reasons.map((r, i) => <li key={i}>{r}</li>)
        ) : (
          <li>No high-risk anomaly signals detected. Normal traffic pattern.</li>
        )}
      </ul>

      {Object.keys(features).length > 0 && (
        <>
          <div style={{ fontSize: '0.8rem', marginBottom: '0.4rem', fontWeight: 700, color: 'var(--text-secondary)' }}>
            Extracted Feature Snapshot:
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.4rem', fontSize: '0.75rem', background: 'rgba(0,0,0,0.3)', padding: '0.5rem', borderRadius: '6px' }}>
            <div>Req/Sec: {features.req_per_sec ? features.req_per_sec.toFixed(1) : 0}</div>
            <div>Burstiness: {features.burstiness ? features.burstiness.toFixed(2) : 0}</div>
            <div>Endpoint Conc: {features.endpoint_concentration ? (features.endpoint_concentration * 100).toFixed(0) : 0}%</div>
            <div>Entropy: {features.entropy ? features.entropy.toFixed(2) : 0}</div>
            <div>Avg Latency: {features.avg_latency ? features.avg_latency.toFixed(1) : 0}ms</div>
            <div>Internal Workload: {features.is_internal_workload ? 'YES' : 'NO'}</div>
          </div>
        </>
      )}
    </div>
  );
}
