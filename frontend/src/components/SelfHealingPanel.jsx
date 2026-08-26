import React from 'react';
import { Activity, ShieldCheck, Zap } from 'lucide-react';

export default function SelfHealingPanel({ recoveryConfidence, isRecovering }) {
  const score = recoveryConfidence ? recoveryConfidence.recovery_confidence : 100.0;
  const ratio = recoveryConfidence ? (recoveryConfidence.healthy_instances_ratio * 100).toFixed(0) : 100;
  const probes = recoveryConfidence ? (recoveryConfidence.health_probe_success_rate * 100).toFixed(0) : 100;
  const latency = recoveryConfidence ? (recoveryConfidence.latency_stability_score * 100).toFixed(0) : 100;

  return (
    <div className="cyber-card">
      <div className="card-title">
        <span>Autonomous Self-Healing Loop</span>
        <span style={{ fontSize: '0.75rem', color: isRecovering ? 'var(--accent-yellow)' : 'var(--accent-green)' }}>
          {isRecovering ? 'RECOVERY RUNNING' : 'RECOVERY READY'}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1rem', alignItems: 'center' }}>
        <div style={{ textAlign: 'center', background: 'rgba(0, 229, 255, 0.05)', padding: '1rem', borderRadius: '10px', border: '1px solid rgba(0, 229, 255, 0.2)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>RECOVERY CONFIDENCE</div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, color: score >= 80 ? 'var(--accent-green)' : score >= 50 ? 'var(--accent-yellow)' : 'var(--accent-red)' }}>
            {score.toFixed(1)}%
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Verification Score</div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '0.5rem 0.75rem', borderRadius: '6px' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Healthy Pool Ratio</div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>{ratio}%</div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '0.5rem 0.75rem', borderRadius: '6px' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Probe Pass Rate</div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-green)' }}>{probes}%</div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '0.5rem 0.75rem', borderRadius: '6px' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Latency Stability</div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-yellow)' }}>{latency}%</div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '0.5rem 0.75rem', borderRadius: '6px' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Self-Healing Mode</div>
            <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--accent-purple)' }}>AUTOMATIC</div>
          </div>
        </div>
      </div>
    </div>
  );
}
