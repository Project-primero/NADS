import React, { useState, useEffect } from 'react';
import { Icon } from '../Icon';
import type { Asset, AllowlistRule } from '../../types';

export function AssetsAllowlistPage() {
  const [tab, setTab] = useState<'assets' | 'allowlist'>('assets');
  const [assets, setAssets] = useState<Asset[]>([]);
  const [allowlist, setAllowlist] = useState<AllowlistRule[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  // New allowlist entry state
  const [newCidr, setNewCidr] = useState('');
  const [newPort, setNewPort] = useState(0);
  const [newDesc, setNewDesc] = useState('');

  // Asset edit state
  const [editingIp, setEditingIp] = useState<string | null>(null);
  const [editHostname, setEditHostname] = useState('');
  const [editOwner, setEditOwner] = useState('');
  const [editDept, setEditDept] = useState('');

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [resA, resL] = await Promise.all([
        fetch('/api/assets'),
        fetch('/api/allowlist')
      ]);
      if (resA.ok) {
        const dataA = await resA.json();
        setAssets(dataA.assets ?? []);
      }
      if (resL.ok) {
        const dataL = await resL.json();
        setAllowlist(dataL.allowlist ?? []);
      }
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  };

  const handleAddAllowlist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCidr) return;
    try {
      const res = await fetch('/api/allowlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cidr_or_ip: newCidr, port: Number(newPort), description: newDesc })
      });
      if (res.ok) {
        setNewCidr('');
        setNewPort(0);
        setNewDesc('');
        fetchData();
      } else {
        const err = await res.json();
        alert(err.detail || 'Failed to add allowlist entry');
      }
    } catch {
      alert('Error contacting server');
    }
  };

  const handleDeleteAllowlist = async (id: number) => {
    try {
      const res = await fetch(`/api/allowlist/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setAllowlist((prev) => prev.filter((r) => r.id !== id));
      }
    } catch {
      /* ignore */
    }
  };

  const handleSaveAsset = async (ip: string) => {
    try {
      const res = await fetch(`/api/assets/${ip}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hostname: editHostname,
          owner: editOwner,
          department: editDept
        })
      });
      if (res.ok) {
        setEditingIp(null);
        fetchData();
      }
    } catch {
      /* ignore */
    }
  };

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1400, margin: '0 auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h2 style={{ fontSize: 24, fontWeight: 700, margin: '0 0 6px 0', color: 'var(--text)' }}>
            Asset Inventory & Trusted Allowlist
          </h2>
          <p style={{ margin: 0, color: 'var(--muted)', fontSize: 14 }}>
            Manage discovered computers, label device owners, and exempt trusted scanners from false alarms.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 6, background: 'var(--card-bg)', padding: 4, borderRadius: 8, border: '1px solid var(--border)' }}>
          <button
            onClick={() => setTab('assets')}
            className="btn"
            style={{
              padding: '6px 14px',
              fontSize: 13,
              background: tab === 'assets' ? 'var(--blue)' : 'transparent',
              color: tab === 'assets' ? '#fff' : 'var(--muted)'
            }}
          >
            Discovered Devices ({assets.length})
          </button>
          <button
            onClick={() => setTab('allowlist')}
            className="btn"
            style={{
              padding: '6px 14px',
              fontSize: 13,
              background: tab === 'allowlist' ? 'var(--blue)' : 'transparent',
              color: tab === 'allowlist' ? '#fff' : 'var(--muted)'
            }}
          >
            Trusted Allowlist ({allowlist.length})
          </button>
        </div>
      </div>

      {tab === 'assets' ? (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
            <thead>
              <tr style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--border)' }}>
                <th style={{ padding: '12px 16px' }}>IP Address</th>
                <th style={{ padding: '12px 16px' }}>Hostname / Label</th>
                <th style={{ padding: '12px 16px' }}>Owner</th>
                <th style={{ padding: '12px 16px' }}>Department</th>
                <th style={{ padding: '12px 16px' }}>Packets</th>
                <th style={{ padding: '12px 16px', textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {assets.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ padding: 32, textAlign: 'center', color: 'var(--muted)' }}>
                    {loading ? 'Discovering network assets…' : 'No network devices discovered yet.'}
                  </td>
                </tr>
              ) : (
                assets.map((a) => {
                  const isEditing = editingIp === a.ip;
                  return (
                    <tr key={a.ip} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace', color: 'var(--blue)' }}>
                        {a.ip}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        {isEditing ? (
                          <input
                            type="text"
                            value={editHostname}
                            onChange={(e) => setEditHostname(e.target.value)}
                            style={{ padding: '4px 8px', background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 4 }}
                          />
                        ) : (
                          <span style={{ fontWeight: 600 }}>{a.hostname || '—'}</span>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        {isEditing ? (
                          <input
                            type="text"
                            value={editOwner}
                            onChange={(e) => setEditOwner(e.target.value)}
                            style={{ padding: '4px 8px', background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 4 }}
                          />
                        ) : (
                          a.owner || '—'
                        )}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        {isEditing ? (
                          <input
                            type="text"
                            value={editDept}
                            onChange={(e) => setEditDept(e.target.value)}
                            style={{ padding: '4px 8px', background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 4 }}
                          />
                        ) : (
                          a.department || '—'
                        )}
                      </td>
                      <td style={{ padding: '12px 16px', color: 'var(--muted)' }}>
                        {a.packet_count?.toLocaleString() || 0}
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        {isEditing ? (
                          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                            <button
                              onClick={() => handleSaveAsset(a.ip)}
                              className="btn btn-primary"
                              style={{ padding: '3px 8px', fontSize: 11 }}
                            >
                              Save
                            </button>
                            <button
                              onClick={() => setEditingIp(null)}
                              className="btn"
                              style={{ padding: '3px 8px', fontSize: 11 }}
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => {
                              setEditingIp(a.ip);
                              setEditHostname(a.hostname);
                              setEditOwner(a.owner);
                              setEditDept(a.department);
                            }}
                            className="btn"
                            style={{ padding: '3px 8px', fontSize: 11, border: '1px solid var(--border)' }}
                          >
                            Edit
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 20 }}>
          {/* Allowlist Table */}
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
              <thead>
                <tr style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--border)' }}>
                  <th style={{ padding: '12px 16px' }}>Trusted IP / CIDR</th>
                  <th style={{ padding: '12px 16px' }}>Port</th>
                  <th style={{ padding: '12px 16px' }}>Description / Purpose</th>
                  <th style={{ padding: '12px 16px', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {allowlist.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ padding: 32, textAlign: 'center', color: 'var(--muted)' }}>
                      No allowlist rules defined. Add trusted scanners or backup IPs to prevent false alarms.
                    </td>
                  </tr>
                ) : (
                  allowlist.map((r) => (
                    <tr key={r.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace', color: '#3fb950', fontWeight: 600 }}>
                        {r.cidr_or_ip}
                      </td>
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace' }}>
                        {r.port === 0 ? 'Any Port' : r.port}
                      </td>
                      <td style={{ padding: '12px 16px', color: 'var(--text)' }}>
                        {r.description || '—'}
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <button
                          onClick={() => handleDeleteAllowlist(r.id)}
                          className="btn"
                          style={{ padding: '3px 8px', fontSize: 11, color: '#ff7b72', border: '1px solid rgba(218,54,51,0.3)' }}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Add Allowlist Card */}
          <div className="card">
            <h3 style={{ margin: '0 0 12px 0', fontSize: 16 }}>+ Add Trusted IP / CIDR</h3>
            <form onSubmit={handleAddAllowlist}>
              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)' }}>IP OR CIDR SUBNET</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 192.168.1.50 or 10.0.0.0/24"
                  value={newCidr}
                  onChange={(e) => setNewCidr(e.target.value)}
                  style={{ width: '100%', padding: '8px 10px', marginTop: 4, background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 13 }}
                />
              </div>

              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)' }}>PORT (0 FOR ALL PORTS)</label>
                <input
                  type="number"
                  value={newPort}
                  onChange={(e) => setNewPort(Number(e.target.value))}
                  style={{ width: '100%', padding: '8px 10px', marginTop: 4, background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 13 }}
                />
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)' }}>DESCRIPTION / ROLE</label>
                <input
                  type="text"
                  placeholder="e.g. Nessus Scanner / NAS Backup"
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  style={{ width: '100%', padding: '8px 10px', marginTop: 4, background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 13 }}
                />
              </div>

              <button type="submit" className="btn btn-primary" style={{ width: '100%' }}>
                Add to Trusted Allowlist
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
