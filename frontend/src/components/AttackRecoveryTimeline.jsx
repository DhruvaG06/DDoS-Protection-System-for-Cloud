import React from 'react';
import { ShieldAlert, RefreshCw, Cpu, CheckCircle2, Zap, ArrowRight } from 'lucide-react';

export default function AttackRecoveryTimeline({ events, recoveryEvents }) {
  // Combine security and recovery events into a single unified timeline
  const unifiedTimeline = [
    ...(events || []).map((e) => ({
      id: e.event_id || Math.random(),
      timestamp: e.timestamp,
      type: 'SECURITY',
      title: `${e.decision} (${e.threat_level})`,
      description: e.reasons && e.reasons.length > 0 ? e.reasons.join(', ') : e.rule_triggered || 'Traffic analyzed',
      origin: e.attack_origin,
      riskScore: e.risk_score,
      decision: e.decision,
    })),
    ...(recoveryEvents || []).map((r) => ({
      id: r.event_id || Math.random(),
      timestamp: r.timestamp,
      type: 'RECOVERY',
      title: r.event_type,
      description: r.trigger_reason || `Recovery action on ${r.instance_id}`,
      instance: r.instance_id,
      confidence: r.recovery_confidence,
    })),
  ].sort((a, b) => b.timestamp - a.timestamp).slice(0, 30);

  return (
    <div className="cyber-card">
      <div className="card-title">
        <span>Attack → Self-Healing Timeline</span>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Autonomous Response Narrative</span>
      </div>

      {/* Sequential Phase Indicator */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', marginBottom: '1rem', fontSize: '0.75rem', fontWeight: 700 }}>
        <span style={{ color: 'var(--accent-red)' }}>1. ATTACK</span>
        <ArrowRight size={12} style={{ color: 'var(--text-muted)' }} />
        <span style={{ color: 'var(--accent-yellow)' }}>2. DETECT</span>
        <ArrowRight size={12} style={{ color: 'var(--text-muted)' }} />
        <span style={{ color: 'var(--accent-cyan)' }}>3. DECIDE</span>
        <ArrowRight size={12} style={{ color: 'var(--text-muted)' }} />
        <span style={{ color: 'var(--accent-blue)' }}>4. MITIGATE</span>
        <ArrowRight size={12} style={{ color: 'var(--text-muted)' }} />
        <span style={{ color: 'var(--accent-purple)' }}>5. HEAL</span>
        <ArrowRight size={12} style={{ color: 'var(--text-muted)' }} />
        <span style={{ color: 'var(--accent-green)' }}>6. RECOVER</span>
      </div>

      <div className="timeline-list">
        {unifiedTimeline.length > 0 ? (
          unifiedTimeline.map((item) => (
            <div
              key={item.id}
              className={`timeline-item ${item.type === 'RECOVERY' ? 'recovery' : item.decision === 'BLOCK' ? 'alert' : ''}`}
            >
              <div style={{ marginTop: '0.1rem' }}>
                {item.type === 'RECOVERY' ? (
                  <RefreshCw size={14} style={{ color: 'var(--accent-green)' }} />
                ) : item.decision === 'BLOCK' ? (
                  <ShieldAlert size={14} style={{ color: 'var(--accent-red)' }} />
                ) : (
                  <Zap size={14} style={{ color: 'var(--accent-cyan)' }} />
                )}
              </div>

              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontWeight: 700, fontSize: '0.85rem' }}>{item.title}</span>
                  <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {new Date(item.timestamp * 1000).toLocaleTimeString()}
                  </span>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                  {item.description}
                </div>
                {item.origin && (
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.1rem' }}>
                    Origin: <span style={{ color: item.origin.includes('INTERNAL') ? 'var(--accent-purple)' : 'var(--accent-blue)' }}>{item.origin}</span>
                  </div>
                )}
              </div>
            </div>
          ))
        ) : (
          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', textAlign: 'center', padding: '1.5rem' }}>
            No security or recovery events recorded yet. Click a demo simulation button below to trigger events!
          </div>
        )}
      </div>
    </div>
  );
}
