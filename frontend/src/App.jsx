import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import ThreatStatusCard from './components/ThreatStatusCard';
import TrafficChart from './components/TrafficChart';
import PolicyDistribution from './components/PolicyDistribution';
import InfrastructureHealth from './components/InfrastructureHealth';
import SelfHealingPanel from './components/SelfHealingPanel';
import AttackRecoveryTimeline from './components/AttackRecoveryTimeline';
import DecisionInspector from './components/DecisionInspector';
import SecurityEventFeed from './components/SecurityEventFeed';
import DemoControls from './components/DemoControls';

export default function App() {
  const [wsConnected, setWsConnected] = useState(false);
  const [securityEvents, setSecurityEvents] = useState([]);
  const [recoveryEvents, setRecoveryEvents] = useState([]);
  const [instances, setInstances] = useState([]);
  const [recoveryConfidence, setRecoveryConfidence] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [trafficHistory, setTrafficHistory] = useState([]);

  // WebSocket connection lifecycle
  useEffect(() => {
    let ws;
    const connectWebSocket = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//localhost:8000/ws/telemetry`;
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        setWsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          if (message.type === 'INITIAL_SNAPSHOT') {
            setSecurityEvents(message.security_events || []);
            setRecoveryEvents(message.recovery_events || []);
            setInstances(message.instances || []);
            setRecoveryConfidence(message.recovery_confidence || null);
          } else if (message.type === 'SECURITY_EVENT') {
            const newEvt = message.event;
            setSecurityEvents((prev) => [newEvt, ...prev.slice(0, 199)]);
            
            // Update rolling traffic chart
            setTrafficHistory((prev) => {
              const nowStr = new Date(newEvt.timestamp * 1000).toLocaleTimeString();
              const lastEntry = prev[prev.length - 1];
              if (lastEntry && lastEntry.time === nowStr) {
                return [
                  ...prev.slice(0, -1),
                  {
                    ...lastEntry,
                    total: lastEntry.total + 1,
                    blocked: lastEntry.blocked + (newEvt.decision === 'BLOCK' ? 1 : 0),
                  },
                ];
              }
              const newEntry = {
                time: nowStr,
                total: 1,
                blocked: newEvt.decision === 'BLOCK' ? 1 : 0,
              };
              return [...prev.slice(-29), newEntry];
            });
          } else if (message.type === 'RECOVERY_EVENT') {
            const newRec = message.event;
            setRecoveryEvents((prev) => [newRec, ...prev.slice(0, 99)]);
          } else if (message.type === 'RESET') {
            setSecurityEvents([]);
            setRecoveryEvents([]);
            setTrafficHistory([]);
            setSelectedEvent(null);
            if (message.instances) setInstances(message.instances);
            if (message.recovery_confidence) setRecoveryConfidence(message.recovery_confidence);
          }
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err);
        }
      };

      ws.onclose = () => {
        setWsConnected(false);
        setTimeout(connectWebSocket, 2000);
      };

      ws.onerror = (err) => {
        ws.close();
      };
    };

    connectWebSocket();
    return () => {
      if (ws) ws.close();
    };
  }, []);

  // Poll instance health fallback every 3s
  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/recovery/status');
        const data = await res.json();
        const instList = data.snapshot?.instances || data.instances;
        if (instList) setInstances(instList);
        const conf = data.verification_metrics || data.recovery_confidence;
        if (conf) setRecoveryConfidence(conf);
      } catch (e) {
        // Fallback silently if offline
      }
    };
    fetchHealth();
    const interval = setInterval(fetchHealth, 3000);
    return () => clearInterval(interval);
  }, []);

  const latestEvent = securityEvents[0] || null;
  const isUnderAttack = latestEvent && (latestEvent.decision === 'BLOCK' || latestEvent.risk_score >= 50);
  const isRecovering = instances.some((i) => i.status === 'RECOVERING' || i.status === 'UNHEALTHY' || i.status === 'ISOLATED');

  const systemStatus = isUnderAttack ? 'ATTACK' : isRecovering ? 'RECOVERING' : 'PROTECTED';

  const policyCounts = securityEvents.reduce(
    (acc, evt) => {
      const dec = evt.decision || 'ALLOW';
      acc[dec] = (acc[dec] || 0) + 1;
      return acc;
    },
    { ALLOW: 0, CHALLENGE: 0, BLOCK: 0 }
  );

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Header systemStatus={systemStatus} wsConnected={wsConnected} />

      <main className="dashboard-grid">
        {/* Row 1: Controls */}
        <div className="col-12">
          <DemoControls />
        </div>

        {/* Row 2: Status, Traffic, Policies */}
        <div className="col-4">
          <ThreatStatusCard latestEvent={latestEvent} isUnderAttack={isUnderAttack} />
        </div>

        <div className="col-5">
          <TrafficChart trafficHistory={trafficHistory} />
        </div>

        <div className="col-3">
          <PolicyDistribution policyCounts={policyCounts} />
        </div>

        {/* Row 3: Cluster Health & Self-Healing */}
        <div className="col-6">
          <InfrastructureHealth instances={instances} />
        </div>

        <div className="col-6">
          <SelfHealingPanel recoveryConfidence={recoveryConfidence} isRecovering={isRecovering} />
        </div>

        {/* Row 4: Timeline Narrative */}
        <div className="col-12">
          <AttackRecoveryTimeline events={securityEvents} recoveryEvents={recoveryEvents} />
        </div>

        {/* Row 5: Deep Dive Event Stream & Inspector */}
        <div className="col-6">
          <SecurityEventFeed
            events={securityEvents}
            onSelectEvent={setSelectedEvent}
            selectedEventId={selectedEvent ? selectedEvent.event_id : null}
          />
        </div>

        <div className="col-6">
          <DecisionInspector selectedEvent={selectedEvent || latestEvent} />
        </div>
      </main>
    </div>
  );
}
