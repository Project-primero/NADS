import { useState, useEffect } from 'react';
import type { Site, SiteCheck } from '../types';
import { ScoreRing, getGrade } from './ScoreRing';
import { FindingSummary } from './FindingSummary';
import { Icon } from './Icon';

interface AddSiteModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSiteAdded?: (site: Site, check?: SiteCheck | null) => void;
  onViewAudit?: (site: Site, check?: SiteCheck | null) => void;
}

export function AddSiteModal({ isOpen, onClose, onSiteAdded, onViewAudit }: AddSiteModalProps) {
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [interval, setIntervalSec] = useState(60);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [errorMsg, setErrorMsg] = useState('');
  const [scanResult, setScanResult] = useState<{ site: Site; check: SiteCheck | null } | null>(null);

  // Close on Escape key
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isScanning) {
        handleClose();
      }
    };
    if (isOpen) {
      window.addEventListener('keydown', handleKey);
    }
    return () => window.removeEventListener('keydown', handleKey);
  }, [isOpen, isScanning]);

  // Animated scan steps for interactive feedback
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    if (isScanning) {
      setScanStep(1);
      timer = setInterval(() => {
        setScanStep((s) => (s < 4 ? s + 1 : s));
      }, 700);
    } else {
      setScanStep(0);
    }
    return () => clearInterval(timer);
  }, [isScanning]);

  if (!isOpen) return null;

  const handleClose = () => {
    setUrl('');
    setName('');
    setIntervalSec(60);
    setErrorMsg('');
    setScanResult(null);
    setIsScanning(false);
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    let cleanUrl = url.trim();
    if (!cleanUrl) {
      setErrorMsg('Target URL is required.');
      return;
    }

    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      cleanUrl = `https://${cleanUrl}`;
    }

    setIsScanning(true);
    setErrorMsg('');
    setScanResult(null);

    try {
      const res = await fetch('/api/sites', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim() || cleanUrl,
          url: cleanUrl,
          interval,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.detail || `Failed to register website (HTTP ${res.status})`);
      } else {
        const resultSite: Site = data.site;
        const resultCheck: SiteCheck | null = data.check || null;
        setScanResult({ site: resultSite, check: resultCheck });
        if (onSiteAdded) {
          onSiteAdded(resultSite, resultCheck);
        }
      }
    } catch {
      setErrorMsg('Network error connecting to NAD backend. Verify the backend is active.');
    } finally {
      setIsScanning(false);
    }
  };

  const steps = [
    'Connecting to origin server...',
    'Performing SSL/TLS cryptographic handshake...',
    'Auditing HTTP security headers, CORS & cookies...',
    'Probing exposed paths & OWASP attack surface...',
  ];

  return (
    <div className="audit-modal-backdrop" onClick={handleClose}>
      <div
        className="audit-modal-container add-site-modal"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: 580 }}
        role="dialog"
        aria-modal="true"
      >
        <div className="audit-modal-topbar">
          <div className="audit-modal-title-area">
            <span className="audit-modal-badge">Interactive Target Scanner</span>
            <h3 className="audit-modal-title" style={{ fontSize: 16 }}>
              {scanResult ? 'Vulnerability Scan Complete' : 'Add Website for Security Monitoring'}
            </h3>
          </div>
          <button
            className="audit-modal-close"
            onClick={handleClose}
            disabled={isScanning}
            aria-label="Close"
          >
            <Icon name="close" size={16} />
          </button>
        </div>

        <div style={{ padding: '20px 24px' }}>
          {!scanResult ? (
            <form onSubmit={handleSubmit}>
              <div style={{ display: 'grid', gap: 14 }}>
                <div>
                  <label className="input-label">Target Website URL *</label>
                  <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                    <span style={{ position: 'absolute', left: 10, color: 'var(--muted)', display: 'flex' }}>
                      <Icon name="globe" size={14} />
                    </span>
                    <input
                      type="text"
                      className="websec-input url-field"
                      style={{ width: '100%', paddingLeft: 32 }}
                      placeholder="e.g. https://yourcompany.com or app.example.org"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      disabled={isScanning}
                      required
                      autoFocus
                    />
                  </div>
                  <span style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4, display: 'block' }}>
                    Enter domain or full URL. Supports public web applications and APIs.
                  </span>
                </div>

                <div>
                  <label className="input-label">Friendly Label / Nickname (Optional)</label>
                  <input
                    type="text"
                    className="websec-input"
                    style={{ width: '100%' }}
                    placeholder="e.g. Production Web Portal, Customer API"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    disabled={isScanning}
                  />
                </div>

                <div>
                  <label className="input-label">Monitoring & Audit Frequency</label>
                  <select
                    className="websec-select"
                    style={{ width: '100%' }}
                    value={interval}
                    onChange={(e) => setIntervalSec(Number(e.target.value))}
                    disabled={isScanning}
                  >
                    <option value={30}>Every 30 seconds (High frequency)</option>
                    <option value={60}>Every 60 seconds (Standard recommendation)</option>
                    <option value={300}>Every 5 minutes</option>
                    <option value={900}>Every 15 minutes</option>
                    <option value={3600}>Every 1 hour</option>
                  </select>
                </div>

                {isScanning && (
                  <div
                    style={{
                      background: 'var(--bg2)',
                      border: '1px solid var(--border)',
                      borderRadius: 8,
                      padding: '14px 16px',
                      display: 'grid',
                      gap: 8,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--blue)', fontWeight: 600, fontSize: 13 }}>
                      <span className="scanning-spinner" />
                      <span>Running comprehensive dynamic vulnerability scan...</span>
                    </div>
                    <div style={{ display: 'grid', gap: 4, marginTop: 4 }}>
                      {steps.map((st, idx) => (
                        <div
                          key={st}
                          style={{
                            fontSize: 12,
                            display: 'flex',
                            alignItems: 'center',
                            gap: 6,
                            color: scanStep > idx ? 'var(--low)' : scanStep === idx + 1 ? 'var(--blue)' : 'var(--muted)',
                          }}
                        >
                          {scanStep > idx ? (
                            <Icon name="check" size={12} />
                          ) : scanStep === idx + 1 ? (
                            <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--blue)' }} />
                          ) : (
                            <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--border)' }} />
                          )}
                          <span>{st}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {errorMsg && (
                  <div className="websec-status-msg err">
                    <Icon name="alert" size={14} />
                    <span>{errorMsg}</span>
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 8 }}>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={handleClose}
                    disabled={isScanning}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={isScanning || !url.trim()}
                    style={{ padding: '8px 20px' }}
                  >
                    <Icon name="zap" size={14} />
                    {isScanning ? 'Scanning...' : 'Scan & Start Monitoring'}
                  </button>
                </div>
              </div>
            </form>
          ) : (
            /* Result Screen */
            <div style={{ display: 'grid', gap: 16 }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 16,
                  background: 'var(--bg2)',
                  border: '1px solid var(--border)',
                  borderRadius: 10,
                  padding: '16px 20px',
                }}
              >
                <ScoreRing
                  score={scanResult.check?.security_score ?? scanResult.site.security_score ?? 100}
                  size={72}
                  strokeWidth={7}
                  showGrade={false}
                />
                <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span
                      style={{
                        fontSize: 16,
                        fontWeight: 800,
                        color: getGrade(scanResult.check?.security_score ?? 100).color,
                      }}
                    >
                      Grade {getGrade(scanResult.check?.security_score ?? 100).grade}
                    </span>
                    <span
                      className={`site-status-pill ${
                        scanResult.check?.up ? 'up' : 'down'
                      }`}
                    >
                      <span className="status-dot" />
                      {scanResult.check?.up ? `UP (${scanResult.check.status_code})` : 'DOWN'}
                    </span>
                  </div>
                  <h4 style={{ margin: 0, fontSize: 15, fontWeight: 700 }}>
                    {scanResult.site.name || scanResult.site.url}
                  </h4>
                  <span style={{ fontSize: 12, color: 'var(--muted)', fontFamily: 'monospace' }}>
                    {scanResult.site.url} · {scanResult.check?.latency_ms ?? 0}ms latency
                  </span>
                </div>
              </div>

              <div>
                <span className="card-sub-label" style={{ display: 'block', marginBottom: 6 }}>
                  Identified Security Findings ({scanResult.check?.findings?.length || 0})
                </span>
                <FindingSummary findings={scanResult.check?.findings || []} />
              </div>

              <div
                style={{
                  background: 'var(--card2)',
                  border: '1px solid var(--border)',
                  borderRadius: 8,
                  padding: '10px 14px',
                  fontSize: 12,
                  color: 'var(--muted)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                }}
              >
                <Icon name="check" size={14} />
                <span>
                  Target successfully added to automated continuous background monitoring (checked every {interval}s).
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 4 }}>
                <button type="button" className="btn btn-secondary" onClick={handleClose}>
                  Done
                </button>
                {onViewAudit && (
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => {
                      const s = scanResult.site;
                      const c = scanResult.check;
                      handleClose();
                      onViewAudit(s, c);
                    }}
                  >
                    <Icon name="shield" size={14} /> View Full Audit Report
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
