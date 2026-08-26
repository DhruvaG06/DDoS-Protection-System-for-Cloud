import React, { useState } from 'react';
import { Play, Square, RefreshCw, Cpu, ShieldAlert, Zap, AlertTriangle } from 'lucide-react';

export default function DemoControls() {
  const [activeAction, setActiveAction] = useState(null);
  const [message, setMessage] = useState('');

  const triggerApi = async (endpoint, label) => {
    setActiveAction(label);
    setMessage(`Triggering ${label}...`);
    try {
      const res = await fetch(`http://localhost:8000${endpoint}`, { method: 'POST' });
      const data = await res.json();
      setMessage(data.message || `${label} executed successfully`);
    } catch (err) {
      setMessage(`Failed to call ${endpoint}: ${err.message}`);
    } finally {
      setTimeout(() => setActiveAction(null), 1000);
    }
  };

  const simulateFailure = async () => {
    setActiveAction('SIMULATE FAILURE');
    setMessage('Simulating container app-1 crash...');
    try {
      const res = await fetch('http://localhost:8000/api/recovery/simulate-failure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ instance_id: 'app-1', reason: 'Dashboard manual fault injection' }),
      });
      const data = await res.json();
      setMessage(data.message || 'Failure simulated on app-1');
    } catch (err) {
      setMessage(`Failed: ${err.message}`);
    } finally {
      setTimeout(() => setActiveAction(null), 1000);
    }
  };

  return (
    <div className="cyber-card">
      <div className="card-title">
        <span>Interactive SIH Demo Control Panel</span>
        <span style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>Real-Time Attack & Healing Scenario Generator</span>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center' }}>
        <button className="btn-cyber" onClick={() => triggerApi('/api/demo/start-normal', 'START NORMAL TRAFFIC')}>
          <Play size={14} /> START NORMAL TRAFFIC
        </button>

        <button className="btn-cyber btn-danger" onClick={() => triggerApi('/api/demo/start-attack', 'START ATTACK SIMULATION')}>
          <ShieldAlert size={14} /> START EXTERNAL DDoS FLOOD
        </button>

        <button className="btn-cyber btn-purple" onClick={() => triggerApi('/api/demo/start-internal-attack', 'START INTERNAL ATTACK')}>
          <Cpu size={14} /> START INTERNAL CLOUD ATTACK
        </button>

        <button className="btn-cyber btn-secondary" onClick={simulateFailure}>
          <AlertTriangle size={14} style={{ color: 'var(--accent-yellow)' }} /> SIMULATE INSTANCE FAILURE
        </button>

        <button className="btn-cyber btn-secondary" onClick={() => triggerApi('/api/demo/stop-attack', 'STOP TRAFFIC')}>
          <Square size={14} /> STOP TRAFFIC
        </button>

        <button className="btn-cyber btn-secondary" onClick={() => triggerApi('/api/demo/reset', 'RESET DEMO')}>
          <RefreshCw size={14} /> RESET DEMO STATE
        </button>
      </div>

      {message && (
        <div style={{ marginTop: '0.75rem', fontSize: '0.8rem', color: 'var(--text-secondary)', background: 'rgba(255,255,255,0.03)', padding: '0.4rem 0.8rem', borderRadius: '4px', borderLeft: '3px solid var(--accent-cyan)' }}>
          {message}
        </div>
      )}
    </div>
  );
}
