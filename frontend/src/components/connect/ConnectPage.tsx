import React, { useState, useEffect } from 'react';
import { Icon } from '../Icon';
import type { HostInterface, ConnectStatus } from '../../types';

interface ConnectPageProps {
  connectStatus: ConnectStatus | null;
  onNavigateToAgents: () => void;
}

export function ConnectPage({ connectStatus, onNavigateToAgents }: ConnectPageProps) {
  const [activeMode, setActiveMode] = useState<string>(connectStatus?.mode ?? 'simulate');
  const [interfaces, setInterfaces] = useState<HostInterface[]>([]);
  const [selectedIface, setSelectedIface] = useState<string>('lo');
  const [bpfFilter, setBpfFilter] = useState<string>('');
  const [promisc, setPromisc] = useState<boolean>(false);

  // Simulator options
  const [intensity, setIntensity] = useState<'low' | 'medium' | 'high' | 'stress'>('medium');
  const [selectedAttacks, setSelectedAttacks] = useState<string[]>(['all']);

  // TAP / Mirror Port options
  const [switchVendor, setSwitchVendor] = useState<'cisco' | 'mikrotik' | 'ubiquiti' | 'linux'>('cisco');
  const [testingTraffic, setTestingTraffic] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string; fix?: string } | null>(null);

  // PCAP Replay options
  const [pcapFile, setPcapFile] = useState<File | null>(null);
  const [pcapSpeed, setPcapSpeed] = useState<string>('instant');
  const [uploadingPcap, setUploadingPcap] = useState(false);
  const [pcapJob, setPcapJob] = useState<any | null>(null);

  // Agent Token Quick-Gen
  const [agentSite, setAgentSite] = useState('University Lab 1');
  const [agentName, setAgentName] = useState('Workstation-Node');
  const [createdToken, setCreatedToken] = useState<string | null>(null);

  // Feedback messages
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    fetchInterfaces();
  }, []);

  const fetchInterfaces = async () => {
    try {
      const res = await fetch('/api/connect/interfaces');
      if (res.ok) {
        const data = await res.json();
        const list: HostInterface[] = data.interfaces ?? [];
        setInterfaces(list);
        if (list.length > 0 && !selectedIface) {
          const def = list.find((i) => i.is_up && !i.is_loopback) || list[0];
          setSelectedIface(def.name);
        }
      }
    } catch {
      /* ignore */
    }
  };

  const handleStartMode = async (mode: string, options: any = {}) => {
    setStatusMsg(null);
    try {
      const res = await fetch('/api/connect/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode, ...options })
      });
      const data = await res.json();
      if (res.ok) {
        setActiveMode(mode);
        setStatusMsg({ type: 'success', text: `Successfully activated ${mode.toUpperCase()} mode!` });
      } else {
        setStatusMsg({ type: 'error', text: data.detail || 'Failed to activate mode' });
      }
    } catch (e: any) {
      setStatusMsg({ type: 'error', text: e.message || 'Connection failed' });
    }
  };

  const handleStopCapture = async () => {
    try {
      await fetch('/api/connect/stop', { method: 'POST' });
      setStatusMsg({ type: 'success', text: 'Capture engine stopped.' });
    } catch {
      setStatusMsg({ type: 'error', text: 'Error stopping capture.' });
    }
  };

  const handleTestTraffic = async () => {
    setTestingTraffic(true);
    setTestResult(null);
    try {
      const res = await fetch('/api/connect/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: selectedIface, duration: 10 })
      });
      const data = await res.json();
      setTestResult({
        ok: data.ok,
        message: data.message || data.error,
        fix: data.fix
      });
    } catch (e: any) {
      setTestResult({
        ok: false,
        message: 'Could not contact server to test interface.',
        fix: 'Verify backend is running.'
      });
    } finally {
      setTestingTraffic(false);
    }
  };

  const handlePcapUpload = async () => {
    if (!pcapFile) return;
    setUploadingPcap(true);
    const form = new FormData();
    form.append('file', pcapFile);
    try {
      const res = await fetch(`/api/pcap/upload?speed=${pcapSpeed}`, {
        method: 'POST',
        body: form
      });
      const data = await res.json();
      if (res.ok) {
        setPcapJob({ id: data.job_id, filename: data.filename, status: 'RUNNING' });
        setStatusMsg({ type: 'success', text: `Uploaded ${data.filename}! Replay in progress.` });
      } else {
        setStatusMsg({ type: 'error', text: data.detail || 'Upload failed' });
      }
    } catch (e: any) {
      setStatusMsg({ type: 'error', text: e.message || 'Upload error' });
    } finally {
      setUploadingPcap(false);
    }
  };

  const handleCreateToken = async () => {
    try {
      const res = await fetch('/api/agents/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: agentName, site: agentSite })
      });
      const data = await res.json();
      if (res.ok) {
        setCreatedToken(data.agent.token);
      }
    } catch {
      /* ignore */
    }
  };

  const toggleAttackCategory = (cat: string) => {
    if (cat === 'all') {
      setSelectedAttacks(['all']);
      return;
    }
    const filtered = selectedAttacks.filter((c) => c !== 'all');
    if (filtered.includes(cat)) {
      const next = filtered.filter((c) => c !== cat);
      setSelectedAttacks(next.length === 0 ? ['all'] : next);
    } else {
      setSelectedAttacks([...filtered, cat]);
    }
  };

  return (
    <div className="connect-page" style={{ padding: '24px 32px', maxWidth: 1400, margin: '0 auto' }}>
      {/* Header Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: 24, fontWeight: 700, margin: '0 0 6px 0', color: 'var(--text, #fff)' }}>
            Universal Connect & Ingestion System
          </h2>
          <p style={{ margin: 0, color: 'var(--muted, #8b949e)', fontSize: 14 }}>
            Feed any network source into the unified 30-rule signature ⊕ machine learning detection pipeline.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <div style={{
            background: 'var(--card-bg, #161b22)',
            border: '1px solid var(--border, #30363d)',
            padding: '8px 16px',
            borderRadius: 8,
            fontSize: 13,
            display: 'flex',
            alignItems: 'center',
            gap: 8
          }}>
            <span style={{
              width: 8, height: 8, borderRadius: '50%',
              backgroundColor: connectStatus?.running ? 'var(--low, #238636)' : 'var(--crit, #da3633)'
            }} />
            <span>Active Source: <b>{connectStatus?.source_info || 'Simulator'}</b></span>
            <span style={{ color: 'var(--blue, #58a6ff)', marginLeft: 8 }}>
              {connectStatus?.pps?.toFixed(0) || 0} pps
            </span>
          </div>
          {connectStatus?.running && (
            <button
              onClick={handleStopCapture}
              className="btn"
              style={{ background: 'rgba(218,54,51,0.2)', color: '#ff7b72', border: '1px solid #da3633' }}
            >
              Stop Capture
            </button>
          )}
        </div>
      </div>

      {statusMsg && (
        <div style={{
          padding: '12px 16px',
          borderRadius: 8,
          marginBottom: 20,
          fontSize: 14,
          backgroundColor: statusMsg.type === 'success' ? 'rgba(35,134,54,0.15)' : 'rgba(218,54,51,0.15)',
          border: `1px solid ${statusMsg.type === 'success' ? '#238636' : '#da3633'}`,
          color: statusMsg.type === 'success' ? '#3fb950' : '#ff7b72'
        }}>
          {statusMsg.text}
        </div>
      )}

      {/* 5 Ingestion Mode Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: 20 }}>
        
        {/* CARD 1: SIMULATOR */}
        <div className="card" style={{ border: connectStatus?.mode === 'simulate' ? '2px solid var(--blue, #58a6ff)' : '1px solid var(--border, #30363d)' }}>
          <div className="card-head" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Icon name="brain" size={18} /> 1. Attack Simulator
            </h3>
            {connectStatus?.mode === 'simulate' && (
              <span className="pill" style={{ background: 'rgba(35,134,54,0.2)', color: '#3fb950' }}>ACTIVE</span>
            )}
          </div>
          <p style={{ fontSize: 13, color: 'var(--muted, #8b949e)', marginTop: 8 }}>
            Simulate 14 enterprise cyber attack classes (SYN floods, Log4Shell, scans, C2 beaconing) against normal traffic.
          </p>

          <div style={{ marginTop: 14 }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)' }}>TRAFFIC INTENSITY</label>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginTop: 6 }}>
              {(['low', 'medium', 'high', 'stress'] as const).map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setIntensity(lvl)}
                  style={{
                    padding: '6px 8px',
                    fontSize: 12,
                    borderRadius: 6,
                    border: intensity === lvl ? '1px solid var(--blue)' : '1px solid var(--border)',
                    background: intensity === lvl ? 'rgba(88,166,255,0.2)' : 'var(--card-bg)',
                    color: intensity === lvl ? 'var(--blue)' : 'var(--text)',
                    cursor: 'pointer'
                  }}
                >
                  {lvl.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          <div style={{ marginTop: 14 }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)' }}>ATTACK CATEGORIES</label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
              {[
                { id: 'all', label: 'All 14 Classes' },
                { id: 'scans', label: 'Port / Xmas Scans' },
                { id: 'floods', label: 'SYN / UDP Floods' },
                { id: 'brute', label: 'SSH / RDP Brute Force' },
                { id: 'web', label: 'Log4Shell / SQLi / XSS' },
                { id: 'c2', label: 'C2 / DNS Tunnel' },
                { id: 'exfil', label: 'Data Exfil' },
              ].map(({ id, label }) => {
                const active = selectedAttacks.includes(id) || selectedAttacks.includes('all');
                return (
                  <button
                    key={id}
                    onClick={() => toggleAttackCategory(id)}
                    style={{
                      padding: '4px 10px',
                      fontSize: 11,
                      borderRadius: 12,
                      cursor: 'pointer',
                      border: active ? '1px solid var(--blue)' : '1px solid var(--border)',
                      background: active ? 'rgba(88,166,255,0.15)' : 'transparent',
                      color: active ? '#79c0ff' : 'var(--muted)'
                    }}
                  >
                    {label}
                  </button>
                );
              })}
            </div>
          </div>

          <button
            onClick={() => handleStartMode('simulate', { intensity, attacks: selectedAttacks })}
            className="btn btn-primary"
            style={{ width: '100%', marginTop: 20 }}
          >
            Start Simulator ({intensity.toUpperCase()})
          </button>
        </div>

        {/* CARD 2: THIS COMPUTER */}
        <div className="card" style={{ border: connectStatus?.mode === 'live' ? '2px solid var(--blue, #58a6ff)' : '1px solid var(--border, #30363d)' }}>
          <div className="card-head" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Icon name="network" size={18} /> 2. This Computer (Local NIC)
            </h3>
            {connectStatus?.mode === 'live' && (
              <span className="pill" style={{ background: 'rgba(35,134,54,0.2)', color: '#3fb950' }}>ACTIVE</span>
            )}
          </div>
          <p style={{ fontSize: 13, color: 'var(--muted, #8b949e)', marginTop: 8 }}>
            Sniff live physical or loopback interfaces on this host using Scapy and raw sockets.
          </p>

          <div style={{ marginTop: 14 }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)' }}>SELECT NETWORK INTERFACE</label>
            <select
              value={selectedIface}
              onChange={(e) => setSelectedIface(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 10px',
                marginTop: 6,
                background: 'var(--bg, #0d1117)',
                color: 'var(--text, #fff)',
                border: '1px solid var(--border, #30363d)',
                borderRadius: 6
              }}
            >
              {interfaces.map((i) => (
                <option key={i.name} value={i.name}>
                  {i.name} — {i.ip || 'No IP'} ({i.status}) {i.is_loopback ? '[Loopback]' : ''}
                </option>
              ))}
            </select>
          </div>

          <div style={{ marginTop: 14 }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)' }}>BPF CAPTURE FILTER (OPTIONAL)</label>
            <input
              type="text"
              placeholder="e.g. tcp and not port 22 and not port 8000"
              value={bpfFilter}
              onChange={(e) => setBpfFilter(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 10px',
                marginTop: 6,
                background: 'var(--bg, #0d1117)',
                color: 'var(--text, #fff)',
                border: '1px solid var(--border, #30363d)',
                borderRadius: 6,
                fontSize: 13
              }}
            />
          </div>

          <button
            onClick={() => handleStartMode('live', { interface: selectedIface, bpf_filter: bpfFilter })}
            className="btn btn-primary"
            style={{ width: '100%', marginTop: 20 }}
          >
            Start Live Capture on {selectedIface}
          </button>
        </div>

        {/* CARD 3: UPLOAD PCAP */}
        <div className="card" style={{ border: connectStatus?.mode === 'pcap' ? '2px solid var(--blue, #58a6ff)' : '1px solid var(--border, #30363d)' }}>
          <div className="card-head" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Icon name="chart" size={18} /> 3. Upload PCAP File
            </h3>
            {connectStatus?.mode === 'pcap' && (
              <span className="pill" style={{ background: 'rgba(35,134,54,0.2)', color: '#3fb950' }}>REPLAYING</span>
            )}
          </div>
          <p style={{ fontSize: 13, color: 'var(--muted, #8b949e)', marginTop: 8 }}>
            Analyze past incidents or Wireshark captures (.pcap / .pcapng) through all 30 detectors & ML.
          </p>

          <div style={{
            border: '2px dashed var(--border, #30363d)',
            padding: '20px 14px',
            borderRadius: 8,
            textAlign: 'center',
            marginTop: 14,
            background: 'rgba(255,255,255,0.02)'
          }}>
            <input
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={(e) => setPcapFile(e.target.files?.[0] || null)}
              style={{ display: 'none' }}
              id="pcap-upload-input"
            />
            <label htmlFor="pcap-upload-input" style={{ cursor: 'pointer', display: 'block' }}>
              <Icon name="link" size={24} />
              <div style={{ fontSize: 13, fontWeight: 600, marginTop: 6 }}>
                {pcapFile ? pcapFile.name : 'Click to select or drag .pcap file'}
              </div>
              <div style={{ fontSize: 11, color: 'var(--muted)' }}>Max size: 100 MB</div>
            </label>
          </div>

          <div style={{ display: 'flex', gap: 10, marginTop: 14, alignItems: 'center' }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)', width: 120 }}>REPLAY SPEED:</label>
            <select
              value={pcapSpeed}
              onChange={(e) => setPcapSpeed(e.target.value)}
              style={{
                flex: 1,
                padding: '6px 8px',
                background: 'var(--bg)',
                color: 'var(--text)',
                border: '1px solid var(--border)',
                borderRadius: 6
              }}
            >
              <option value="instant">Instant (Fastest Analysis)</option>
              <option value="realtime">1x (Real-Time Timestamps)</option>
              <option value="5x">5x Fast Forward</option>
              <option value="10x">10x Speed</option>
            </select>
          </div>

          <button
            onClick={handlePcapUpload}
            disabled={!pcapFile || uploadingPcap}
            className="btn btn-primary"
            style={{ width: '100%', marginTop: 16 }}
          >
            {uploadingPcap ? 'Uploading & Analyzing…' : 'Start PCAP Replay'}
          </button>
        </div>

        {/* CARD 4: MIRROR PORT / SPAN / TAP */}
        <div className="card">
          <div className="card-head" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Icon name="radio" size={18} /> 4. Mirror Port / Switch SPAN
            </h3>
            <span className="pill" style={{ background: 'rgba(88,166,255,0.15)', color: '#58a6ff' }}>ENTERPRISE</span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--muted, #8b949e)', marginTop: 8 }}>
            Connect to a Cisco, MikroTik, or Ubiquiti switch mirror port to inspect entire office or campus traffic.
          </p>

          {/* Vendor Selector */}
          <div style={{ display: 'flex', gap: 6, marginTop: 12 }}>
            {(['cisco', 'mikrotik', 'ubiquiti', 'linux'] as const).map((v) => (
              <button
                key={v}
                onClick={() => setSwitchVendor(v)}
                style={{
                  padding: '4px 8px',
                  fontSize: 11,
                  borderRadius: 4,
                  cursor: 'pointer',
                  border: switchVendor === v ? '1px solid var(--blue)' : '1px solid var(--border)',
                  background: switchVendor === v ? 'rgba(88,166,255,0.2)' : 'transparent',
                  color: switchVendor === v ? 'var(--blue)' : 'var(--muted)'
                }}
              >
                {v.toUpperCase()}
              </button>
            ))}
          </div>

          {/* Copy-Paste Switch Config Guide */}
          <div style={{
            background: 'var(--bg, #0d1117)',
            padding: 10,
            borderRadius: 6,
            marginTop: 10,
            fontSize: 11,
            fontFamily: 'monospace',
            border: '1px solid var(--border)'
          }}>
            {switchVendor === 'cisco' && (
              <>
                monitor session 1 source interface Gi0/1 - 24 both<br />
                monitor session 1 destination interface Gi0/48
              </>
            )}
            {switchVendor === 'mikrotik' && (
              <>
                /interface ethernet switch<br />
                set mirror-source=ether1 mirror-target=ether5
              </>
            )}
            {switchVendor === 'ubiquiti' && (
              <>
                configure<br />
                set interfaces ethernet eth0 mirror eth1<br />
                commit
              </>
            )}
            {switchVendor === 'linux' && (
              <>
                sudo ip link set dev {selectedIface} promisc on<br />
                sudo tc qdisc add dev eth0 ingress<br />
                sudo tc filter add dev eth0 parent ffff: matchall action mirred egress mirror dev {selectedIface}
              </>
            )}
          </div>

          <div style={{ display: 'flex', gap: 10, marginTop: 14 }}>
            <button
              onClick={handleTestTraffic}
              disabled={testingTraffic}
              className="btn"
              style={{ flex: 1, border: '1px solid var(--border)', background: 'rgba(255,255,255,0.05)' }}
            >
              {testingTraffic ? 'Testing 10s Traffic…' : `10s Link Test (${selectedIface})`}
            </button>
            <button
              onClick={() => handleStartMode('live', { interface: selectedIface, promiscuous: true })}
              className="btn btn-primary"
              style={{ flex: 1 }}
            >
              Activate TAP
            </button>
          </div>

          {testResult && (
            <div style={{
              marginTop: 10,
              padding: 10,
              borderRadius: 6,
              fontSize: 12,
              background: testResult.ok ? 'rgba(35,134,54,0.1)' : 'rgba(218,54,51,0.1)',
              border: `1px solid ${testResult.ok ? '#238636' : '#da3633'}`,
              color: testResult.ok ? '#3fb950' : '#ff7b72'
            }}>
              <b>{testResult.message}</b>
              {testResult.fix && <div style={{ marginTop: 4, whiteSpace: 'pre-line', fontSize: 11 }}>{testResult.fix}</div>}
            </div>
          )}
        </div>

        {/* CARD 5: REMOTE AGENTS (MULTI-COMPUTER & UNIVERSITIES) */}
        <div className="card" style={{ gridColumn: '1 / -1', border: '1px solid var(--border)' }}>
          <div className="card-head" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Icon name="desktop" size={18} /> 5. Remote Multi-Computer Agents (Universities & Organizations)
              </h3>
              <p style={{ fontSize: 13, color: 'var(--muted)', margin: '4px 0 0 0' }}>
                Deploy lightweight agents to university lab workstations, branch offices, and servers to detect threats across the whole organization.
              </p>
            </div>
            <button
              onClick={onNavigateToAgents}
              className="btn btn-primary"
              style={{ fontSize: 13 }}
            >
              View Connected Computers ({connectStatus?.online_agents ?? 0} Online) ➔
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16, marginTop: 16 }}>
            <div>
              <h4 style={{ margin: '0 0 8px 0', fontSize: 13, color: 'var(--text)' }}>Generate Endpoint Token</h4>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  type="text"
                  placeholder="Site (e.g. CS Lab 2)"
                  value={agentSite}
                  onChange={(e) => setAgentSite(e.target.value)}
                  style={{ flex: 1, padding: '6px 10px', background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }}
                />
                <input
                  type="text"
                  placeholder="Node Name"
                  value={agentName}
                  onChange={(e) => setAgentName(e.target.value)}
                  style={{ flex: 1, padding: '6px 10px', background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }}
                />
                <button onClick={handleCreateToken} className="btn btn-primary" style={{ fontSize: 12 }}>
                  Create
                </button>
              </div>

              {createdToken && (
                <div style={{ marginTop: 10, padding: 8, background: 'rgba(88,166,255,0.1)', border: '1px solid var(--blue)', borderRadius: 6, fontSize: 11 }}>
                  <b>New Token:</b> <code style={{ color: '#79c0ff' }}>{createdToken}</code>
                </div>
              )}
            </div>

            <div>
              <h4 style={{ margin: '0 0 8px 0', fontSize: 13, color: 'var(--text)' }}>One-Line Terminal Install Command</h4>
              <div style={{
                background: 'var(--bg)',
                padding: '10px 12px',
                borderRadius: 6,
                fontFamily: 'monospace',
                fontSize: 12,
                border: '1px solid var(--border)',
                wordBreak: 'break-all'
              }}>
                curl -sSL http://{window.location.hostname}:8000/api/agents/install.sh | bash -s -- {createdToken || '&lt;TOKEN&gt;'} "{agentSite}"
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
