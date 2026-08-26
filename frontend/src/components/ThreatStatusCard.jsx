import React from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle, Cpu, Globe } from 'lucide-react';

export default function ThreatStatusCard({ latestEvent, isUnderAttack }) {
  const riskScore = latestEvent ? latestEvent.risk_score : 0;
  const threatLevel = latestEvent ? latestEvent.threat_level || 'LOW' : 'LOW';
  const decision = latestEvent ? latestEvent.decision || 'ALLOW' : 'ALLOW';
  const origin = latestEvent ? latestEvent.attack_origin || 'EXTERNAL' : 'EXTERNAL';
  const isInternal = origin.toUpperCase().includes('INTERNAL');

  const getMeterColor = (score) => {
    if (score >= 70) return 'var(--accent-red)';
    if (score >= 35) return 'var(--accent-yellow)';
    return 'var(--accent-green)';
  };

  return (
    <div className={`cyber-card ${isUnderAttack ? 'alert-active' : ''}`}>
      <div className="card-title">
        <span>Active Threat Status</span>
        {isInternal ? (
          <span className="badge badge-internal">
            <Cpu size={12} /> INTERNAL CLOUD WORKLOAD
          </span>
        ) : (
          <span className="badge badge-external">
            <Globe size={12} /> EXTERNAL INTERNET
          </span>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', alignItems: 'center' }}>
        <div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>THREAT LEVEL</div>
          <div
            style={{
              fontSize: '1.8rem',
              fontWeight: 800,
              color: threatLevel === 'HIGH' || threatLevel === 'CRITICAL' ? 'var(--accent-red)' : threatLevel === 'MEDIUM' ? 'var(--accent-yellow)' : 'var(--accent-green)',
            }}
          >
            {threatLevel}
          </div>
        </div>

        <div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>POLICY DECISION</div>
          <div style={{ marginTop: '0.2rem' }}>
            <span className={`badge badge-${decision.toLowerCase()}`} style={{ fontSize: '0.9rem', padding: '0.4rem 0.8rem' }}>
              {decision}
            </span>
          </div>
        </div>
      </div>

      <div style={{ marginTop: '1.2rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}>
          <span style={{ color: 'var(--text-secondary)' }}>Risk Score</span>
          <span className="font-mono" style={{ fontWeight: 700, color: getMeterColor(riskScore) }}>
            {riskScore.toFixed(1)} / 100
          </span>
        </div>
        <div className="risk-meter-bg">
          <div
            className="risk-meter-fill"
            style={{
              width: `${Math.min(100, Math.max(2, riskScore))}%`,
              backgroundColor: getMeterColor(riskScore),
            }}
          />
        </div>
      </div>

      <div style={{ marginTop: '1rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
        Mitigation: {decision === 'BLOCK' ? 'IP Rate-Limit & Drop' : decision === 'CHALLENGE' ? 'CAPTCHA Challenge Sent' : 'Allowed via Gateway'}
      </div>
    </div>
  );
}
