import React, { useState, useEffect } from 'react';
import { Icon } from '../Icon';
import type { Agent } from '../../types';

interface AgentsPageProps {
  onBackToConnect: () => void;
}

export function AgentsPage({ onBackToConnect }: AgentsPageProps) {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedSite, setSelectedSite] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [showModal, setShowModal] = useState<boolean>(false);
  const [newName, setNewName] = useState<string>('Lab-PC-01');
  const [newSite, setNewSite] = useState<string>('CS Department Lab');
  const [newCreatedToken, setNewCreatedToken] = useState<string | null>(null);

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 4000);
    return () => clearInterval(interval);
  }, []);

  const fetchAgents = async () => {
    try {
      const res = await fetch('/api/agents');
      if (res.ok) {
        const data = await res.json();
        setAgents(data.agents ?? []);
      }
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeAgent = async (agentId: string) => {
    if (!confirm(`Are you sure you want to revoke agent ${agentId}? It will be immediately disconnected.`)) {
      return;
    }
    try {
      const res = await fetch(`/api/agents/${agentId}`, { method: 'DELETE' });
      if (res.ok) {
        setAgents((prev) => prev.filter((a) => a.agent_id !== agentId));
      }
    } catch {
      alert('Failed to revoke agent.');
    }
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/agents/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newName, site: newSite })
      });
      const data = await res.json();
      if (res.ok) {
        setNewCreatedToken(data.agent.token);
        fetchAgents();
      }
    } catch {
      /* ignore */
    }
  };

  const sites = Array.from(new Set(agents.map((a) => a.site).filter(Boolean)));

  const filteredAgents = agents.filter((a) => {
    if (selectedSite !== 'all' && a.site !== selectedSite) return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      return (
        a.name.toLowerCase().includes(q) ||
        a.hostname.toLowerCase().includes(q) ||
        a.ip.toLowerCase().includes(q) ||
        a.site.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const onlineCount = agents.filter((a) => a.status === 'ONLINE').length;

  return (
    <div className="agents-page" style={{ padding: '24px 32px', maxWidth: 1400, margin: '0 auto' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <button
            onClick={onBackToConnect}
            className="btn"
            style={{ marginBottom: 8, padding: '4px 10px', fontSize: 12, border: '1px solid var(--border)' }}
          >
            ← Back to Connect Overview
          </button>
          <h2 style={{ fontSize: 24, fontWeight: 700, margin: '0 0 6px 0', color: 'var(--text)' }}>
            Connected Computers & University Lab Endpoints
          </h2>
          <p style={{ margin: 0, color: 'var(--muted)', fontSize: 14 }}>
            Monitor real-world endpoints and servers streaming telemetry to this central Network Anomaly Detection SOC console.
          </p>
        </div>

        <button
          onClick={() => { setNewCreatedToken(null); setShowModal(true); }}
          className="btn btn-primary"
          style={{ display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Icon name="link" size={16} /> + Connect New Computer
        </button>
      </div>

      {/* KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, marginBottom: 20 }}>
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, color: 'var(--muted)', fontWeight: 600 }}>TOTAL COMPUTERS</div>
          <div style={{ fontSize: 26, fontWeight: 700, marginTop: 4, color: 'var(--text)' }}>{agents.length}</div>
          <div style={{ fontSize: 12, color: 'var(--blue)', marginTop: 4 }}>Registered across {sites.length || 1} site(s)</div>
        </div>

        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, color: 'var(--muted)', fontWeight: 600 }}>ONLINE & STREAMING</div>
          <div style={{ fontSize: 26, fontWeight: 700, marginTop: 4, color: onlineCount > 0 ? '#3fb950' : 'var(--muted)' }}>
            {onlineCount}
          </div>
          <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>Live active endpoints</div>
        </div>

        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, color: 'var(--muted)', fontWeight: 600 }}>AGGREGATE THROUGHPUT</div>
          <div style={{ fontSize: 26, fontWeight: 700, marginTop: 4, color: 'var(--blue)' }}>
            {agents.reduce((acc, a) => acc + (a.pps || 0), 0).toFixed(0)} pps
          </div>
          <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>Incoming telemetry</div>
        </div>
      </div>

      {/* Filter Row */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
        <input
          type="text"
          placeholder="Search by computer name, IP, or hostname…"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{
            flex: 1,
            padding: '8px 12px',
            background: 'var(--card-bg, #161b22)',
            color: 'var(--text, #fff)',
            border: '1px solid var(--border, #30363d)',
            borderRadius: 6,
            fontSize: 13
          }}
        />

        <select
          value={selectedSite}
          onChange={(e) => setSelectedSite(e.target.value)}
          style={{
            padding: '8px 12px',
            background: 'var(--card-bg, #161b22)',
            color: 'var(--text, #fff)',
            border: '1px solid var(--border, #30363d)',
            borderRadius: 6,
            fontSize: 13
          }}
        >
          <option value="all">All Sites / Departments</option>
          {sites.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      {/* Endpoints Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
          <thead>
            <tr style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--border)' }}>
              <th style={{ padding: '12px 16px' }}>Status</th>
              <th style={{ padding: '12px 16px' }}>Computer / Node</th>
              <th style={{ padding: '12px 16px' }}>Site / Dept</th>
              <th style={{ padding: '12px 16px' }}>IP & OS</th>
              <th style={{ padding: '12px 16px' }}>Live Rate</th>
              <th style={{ padding: '12px 16px' }}>Total Packets</th>
              <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredAgents.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: 32, textAlign: 'center', color: 'var(--muted)' }}>
                  {loading ? 'Loading computers…' : 'No computers connected yet. Click "+ Connect New Computer" to get started.'}
                </td>
              </tr>
            ) : (
              filteredAgents.map((a) => {
                const isOnline = a.status === 'ONLINE';
                return (
                  <tr key={a.agent_id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '12px 16px' }}>
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: 6,
                        padding: '3px 8px', borderRadius: 12, fontSize: 11, fontWeight: 600,
                        backgroundColor: isOnline ? 'rgba(35,134,54,0.15)' : 'rgba(139,148,158,0.15)',
                        color: isOnline ? '#3fb950' : '#8b949e',
                        border: `1px solid ${isOnline ? '#238636' : '#30363d'}`
                      }}>
                        <span style={{
                          width: 6, height: 6, borderRadius: '50%',
                          backgroundColor: isOnline ? '#3fb950' : '#8b949e'
                        }} />
                        {a.status}
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text)' }}>{a.name}</div>
                      <div style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'monospace' }}>{a.agent_id}</div>
                    </td>
                    <td style={{ padding: '12px 16px', color: 'var(--text)' }}>{a.site}</td>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ fontFamily: 'monospace', color: 'var(--blue)' }}>{a.ip || 'Pending'}</div>
                      <div style={{ fontSize: 11, color: 'var(--muted)' }}>{a.os || a.hostname || 'Linux/Windows'}</div>
                    </td>
                    <td style={{ padding: '12px 16px', fontWeight: 600 }}>{a.pps?.toFixed(0) || 0} pps</td>
                    <td style={{ padding: '12px 16px', color: 'var(--muted)' }}>{a.total_packets?.toLocaleString() || 0}</td>
                    <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                      <button
                        onClick={() => handleRevokeAgent(a.agent_id)}
                        className="btn"
                        style={{ padding: '4px 10px', fontSize: 11, color: '#ff7b72', border: '1px solid rgba(218,54,51,0.4)', background: 'transparent' }}
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Modal to Register New Computer */}
      {showModal && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div className="card" style={{ maxWidth: 540, width: '90%', padding: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ margin: 0, fontSize: 18 }}>Connect Real Computer or Server</h3>
              <button onClick={() => setShowModal(false)} className="btn" style={{ padding: '2px 8px' }}>✕</button>
            </div>

            {!newCreatedToken ? (
              <form onSubmit={handleCreateToken}>
                <div style={{ marginBottom: 14 }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)' }}>COMPUTER / NODE NAME</label>
                  <input
                    type="text"
                    required
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    placeholder="e.g. Lab-PC-01 or Finance-Server"
                    style={{ width: '100%', padding: '8px 10px', marginTop: 4, background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 6 }}
                  />
                </div>

                <div style={{ marginBottom: 16 }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)' }}>SITE / DEPARTMENT</label>
                  <input
                    type="text"
                    required
                    value={newSite}
                    onChange={(e) => setNewSite(e.target.value)}
                    placeholder="e.g. Computer Science Lab 1"
                    style={{ width: '100%', padding: '8px 10px', marginTop: 4, background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 6 }}
                  />
                </div>

                <button type="submit" className="btn btn-primary" style={{ width: '100%' }}>
                  Generate Agent Token & Command
                </button>
              </form>
            ) : (
              <div>
                <div style={{ padding: 12, background: 'rgba(35,134,54,0.1)', border: '1px solid #238636', borderRadius: 6, marginBottom: 16 }}>
                  <div style={{ fontWeight: 600, color: '#3fb950', fontSize: 13 }}>Token Created Successfully!</div>
                  <div style={{ fontSize: 12, marginTop: 4 }}>Run this command on the target computer to connect it:</div>
                </div>

                <div style={{
                  background: 'var(--bg)',
                  padding: 12,
                  borderRadius: 6,
                  fontFamily: 'monospace',
                  fontSize: 12,
                  border: '1px solid var(--border)',
                  wordBreak: 'break-all',
                  marginBottom: 16
                }}>
                  curl -sSL http://{window.location.hostname}:8000/api/agents/install.sh | bash -s -- {newCreatedToken} "{newSite}" "{newName}"
                </div>

                <button onClick={() => setShowModal(false)} className="btn btn-primary" style={{ width: '100%' }}>
                  Done
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
