import React from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

export default function TrafficChart({ trafficHistory }) {
  return (
    <div className="cyber-card">
      <div className="card-title">
        <span>Live Ingress Traffic Volume</span>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Real-Time Requests/Sec</span>
      </div>

      <div style={{ width: '100%', height: 220 }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={trafficHistory} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#00e5ff" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#00e5ff" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ff1744" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#ff1744" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="time" stroke="#64748b" fontSize={11} tickLine={false} />
            <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
            <Tooltip
              contentStyle={{
                backgroundColor: 'rgba(10, 13, 20, 0.95)',
                borderColor: 'rgba(255, 255, 255, 0.1)',
                borderRadius: '8px',
                fontSize: '12px',
                boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
              }}
            />
            <Area type="monotone" dataKey="total" stroke="#00e5ff" fillOpacity={1} fill="url(#colorTotal)" name="Total Requests" />
            <Area type="monotone" dataKey="blocked" stroke="#ff1744" fillOpacity={1} fill="url(#colorBlocked)" name="Blocked Requests" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
