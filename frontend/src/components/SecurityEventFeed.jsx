import React, { useState } from 'react';
import { Filter, Eye } from 'lucide-react';

export default function SecurityEventFeed({ events, onSelectEvent, selectedEventId }) {
  const [filter, setFilter] = useState('ALL');

  const filteredEvents = (events || []).filter((e) => {
    if (filter === 'ALL') return true;
    return (e.decision || '').toUpperCase() === filter;
  });

  return (
    <div className="cyber-card">
      <div className="card-title">
        <span>Live Security Event Stream</span>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          {['ALL', 'BLOCK', 'CHALLENGE', 'ALLOW'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                background: filter === f ? 'var(--accent-cyan)' : 'rgba(255,255,255,0.05)',
                color: filter === f ? '#000' : 'var(--text-secondary)',
                border: 'none',
                padding: '0.2rem 0.5rem',
                borderRadius: '4px',
                fontSize: '0.7rem',
                fontWeight: 700,
                cursor: 'pointer',
              }}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="timeline-list" style={{ maxHeight: 260 }}>
        {filteredEvents.length > 0 ? (
          filteredEvents.map((evt, idx) => (
            <div
              key={evt.event_id || idx}
              onClick={() => onSelectEvent(evt)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.5rem 0.75rem',
                background: selectedEventId === evt.event_id ? 'rgba(0, 229, 255, 0.12)' : 'rgba(255, 255, 255, 0.02)',
                border: selectedEventId === evt.event_id ? '1px solid var(--accent-cyan)' : '1px solid var(--border-subtle)',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '0.8rem',
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span className={`badge badge-${(evt.decision || 'ALLOW').toLowerCase()}`} style={{ fontSize: '0.65rem' }}>
                    {evt.decision || 'ALLOW'}
                  </span>
                  <span style={{ fontWeight: 600 }}>{evt.source || 'Anonymous IP'}</span>
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.1rem' }}>
                  Origin: {evt.attack_origin || 'EXTERNAL'} | Endpoint: {evt.endpoint || '/'}
                </div>
              </div>

              <div style={{ textAlign: 'right' }}>
                <div className="font-mono" style={{ fontWeight: 700, color: evt.risk_score >= 70 ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                  {evt.risk_score ? evt.risk_score.toFixed(1) : 0}/100
                </div>
                <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                  {new Date(evt.timestamp * 1000).toLocaleTimeString()}
                </div>
              </div>
            </div>
          ))
        ) : (
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textAlign: 'center', padding: '1rem' }}>
            No security events matching filter '{filter}'.
          </div>
        )}
      </div>
    </div>
  );
}
