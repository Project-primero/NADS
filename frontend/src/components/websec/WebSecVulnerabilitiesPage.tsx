import { useMemo, useState } from 'react';
import type { Site, SiteFinding } from '../../types';
import { Icon } from '../Icon';

interface WebSecVulnerabilitiesPageProps {
  sites: Site[];
  onOpenAudit: (site: Site) => void;
}

interface EnrichedFinding extends SiteFinding {
  site: Site;
}

function getSnippet(finding: SiteFinding): string {
  const t = (finding.title + ' ' + (finding.category || '')).toLowerCase();
  if (t.includes('hsts')) {
    return `# Nginx HSTS Configuration\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`;
  }
  if (t.includes('csp') || t.includes('content security')) {
    return `# Nginx Strict Content-Security-Policy\nadd_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';" always;`;
  }
  if (t.includes('clickjacking') || t.includes('x-frame')) {
    return `# Nginx Clickjacking Mitigation\nadd_header X-Frame-Options "DENY" always;\n# Apache .htaccess\nHeader always append X-Frame-Options "DENY"`;
  }
  if (t.includes('content-type') || t.includes('nosniff')) {
    return `# MIME Sniffing Prevention\nadd_header X-Content-Type-Options "nosniff" always;`;
  }
  if (t.includes('referrer')) {
    return `# Referrer Policy Control\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;`;
  }
  if (t.includes('permissions')) {
    return `# Permissions Policy\nadd_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;`;
  }
  if (t.includes('coop') || t.includes('corp')) {
    return `# Cross-Origin Isolation\nadd_header Cross-Origin-Opener-Policy "same-origin" always;\nadd_header Cross-Origin-Resource-Policy "same-origin" always;`;
  }
  if (t.includes('cors')) {
    return `# Restricted CORS Allowlist\nif ($http_origin ~* "^https?://(trusted\\.domain\\.com)$") {\n    add_header Access-Control-Allow-Origin "$http_origin" always;\n    add_header Access-Control-Allow-Credentials "true" always;\n}`;
  }
  if (t.includes('trace') || t.includes('method')) {
    return `# Block TRACE/TRACK methods\nif ($request_method ~ ^(TRACE|TRACK)$) {\n    return 405;\n}`;
  }
  if (t.includes('sri') || t.includes('integrity')) {
    return `<!-- Subresource Integrity Example -->\n<script src="https://cdn.example.com/lib.js"\n        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"\n        crossorigin="anonymous"></script>`;
  }
  if (t.includes('cookie')) {
    return `# Set-Cookie Flags\nSet-Cookie: session_id=token123; Secure; HttpOnly; SameSite=Strict; Path=/;`;
  }
  return `# Configuration Fix Guidance\n${finding.remediation || 'Refer to vendor documentation to apply recommended hardening.'}`;
}

export function WebSecVulnerabilitiesPage({
  sites,
  onOpenAudit,
}: WebSecVulnerabilitiesPageProps) {
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [selectedSiteId, setSelectedSiteId] = useState<number | 'ALL'>('ALL');
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Flatten and enrich findings from all sites
  const allFindings = useMemo(() => {
    const list: EnrichedFinding[] = [];
    for (const site of sites) {
      for (const f of site.findings ?? []) {
        list.push({ ...f, site });
      }
    }
    return list;
  }, [sites]);

  // Unique categories
  const categories = useMemo(() => {
    const set = new Set<string>();
    for (const f of allFindings) {
      if (f.category) set.add(f.category);
    }
    return Array.from(set).sort();
  }, [allFindings]);

  // Counts by severity
  const counts = useMemo(() => {
    return {
      ALL: allFindings.length,
      CRITICAL: allFindings.filter((f) => f.severity === 'CRITICAL').length,
      HIGH: allFindings.filter((f) => f.severity === 'HIGH').length,
      MEDIUM: allFindings.filter((f) => f.severity === 'MEDIUM').length,
      LOW: allFindings.filter((f) => f.severity === 'LOW').length,
      INFO: allFindings.filter((f) => f.severity === 'INFO').length,
    };
  }, [allFindings]);

  // Filtered list
  const filteredFindings = useMemo(() => {
    let list = allFindings;

    if (severityFilter !== 'ALL') {
      list = list.filter((f) => f.severity === severityFilter);
    }

    if (selectedSiteId !== 'ALL') {
      list = list.filter((f) => f.site.id === selectedSiteId);
    }

    if (categoryFilter !== 'ALL') {
      list = list.filter((f) => f.category === categoryFilter);
    }

    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q) ||
          (f.cwe && f.cwe.toLowerCase().includes(q)) ||
          (f.mitre && f.mitre.toLowerCase().includes(q)) ||
          (f.evidence && f.evidence.toLowerCase().includes(q)) ||
          f.site.url.toLowerCase().includes(q) ||
          (f.site.name && f.site.name.toLowerCase().includes(q))
      );
    }

    // Sort: Critical first, then High, Medium, Low, Info
    const order: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 2,
      LOW: 3,
      INFO: 4,
    };
    return list.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  }, [allFindings, severityFilter, selectedSiteId, categoryFilter, search]);

  const copyFix = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2500);
  };

  return (
    <div className="websec-page-wrap">
      {/* ── Page Header ── */}
      <div className="websec-page-header">
        <div>
          <h2>Vulnerabilities &amp; Findings Catalog</h2>
          <p>
            Unified inventory of security deficiencies, attack surface disclosures, misconfigurations,
            and cryptographic weaknesses detected across your target fleet.
          </p>
        </div>
      </div>

      {/* ── Severity Filter Tabs ── */}
      <div className="vuln-tabs-bar">
        {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((sev) => (
          <button
            key={sev}
            className={`vuln-tab-btn ${sev.toLowerCase()} ${severityFilter === sev ? 'active' : ''}`}
            onClick={() => setSeverityFilter(sev)}
          >
            <span>{sev === 'ALL' ? 'All Findings' : sev}</span>
            <span className="vuln-tab-count">{counts[sev]}</span>
          </button>
        ))}
      </div>

      {/* ── Filters & Search Row ── */}
      <div className="websec-controls-row" style={{ marginTop: 12 }}>
        <div className="websec-search-input-wrap">
          <Icon name="search" size={14} />
          <input
            type="text"
            placeholder="Search by title, CWE ID, MITRE technique, evidence, or domain..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && <button onClick={() => setSearch('')}>×</button>}
        </div>

        <div className="websec-filter-group">
          <select
            value={selectedSiteId}
            onChange={(e) => setSelectedSiteId(e.target.value === 'ALL' ? 'ALL' : Number(e.target.value))}
            className="filter-select"
          >
            <option value="ALL">All Monitored Targets ({sites.length})</option>
            {sites.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name || s.url}
              </option>
            ))}
          </select>

          {categories.length > 0 && (
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="filter-select"
            >
              <option value="ALL">All Categories</option>
              {categories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          )}
        </div>
      </div>

      {/* ── Findings List ── */}
      {filteredFindings.length === 0 ? (
        <div className="card websec-empty-state">
          <Icon name="check" size={36} />
          <h4>No Matching Vulnerability Findings</h4>
          <p>
            {allFindings.length === 0
              ? 'No vulnerabilities have been recorded yet. Launch a scan on a monitored target to populate the catalog.'
              : 'No findings match the current filter selection. Reset filters to review all discovered issues.'}
          </p>
        </div>
      ) : (
        <div className="vuln-catalog-list">
          {filteredFindings.map((f, idx) => {
            const cardId = `${f.site.id}-${f.title}-${idx}`;
            const snippet = getSnippet(f);
            return (
              <div key={cardId} className={`vuln-card ${f.severity.toLowerCase()}`}>
                <div className="vuln-card-header">
                  <div className="vuln-card-title-group">
                    <span className={`finding-chip ${f.severity.toLowerCase()}`}>{f.severity}</span>
                    <h4 className="vuln-card-title">{f.title}</h4>
                    {f.category && <span className="vuln-cat-chip">{f.category}</span>}
                  </div>

                  <div className="vuln-card-origin">
                    <button
                      className="btn btn-sm btn-ghost"
                      onClick={() => onOpenAudit(f.site)}
                      title="Open full interactive audit report modal for this target"
                    >
                      <Icon name="globe" size={12} /> {f.site.name || f.site.url} →
                    </button>
                  </div>
                </div>

                <div className="vuln-card-body">
                  <p className="vuln-desc">{f.description}</p>

                  {f.evidence && (
                    <div className="vuln-evidence-block">
                      <span className="block-label">Observed Technical Evidence:</span>
                      <pre className="evidence-code">{f.evidence}</pre>
                    </div>
                  )}

                  <div className="vuln-remediation-block">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                      <span className="block-label">Prescriptive Remediation Action:</span>
                      <button
                        className="btn btn-sm btn-ghost copy-fix-btn"
                        onClick={() => copyFix(snippet, cardId)}
                        title="Copy code configuration snippet"
                      >
                        <Icon name="file" size={12} />
                        {copiedId === cardId ? 'Copied to Clipboard ✓' : 'Copy Config Fix'}
                      </button>
                    </div>
                    <p className="remediation-text">{f.remediation}</p>
                    <pre className="remediation-code-preview">{snippet}</pre>
                  </div>
                </div>

                <div className="vuln-card-footer">
                  <div className="vuln-standards-chips">
                    {f.cwe && <span className="code-badge">CWE: {f.cwe}</span>}
                    {f.mitre && <span className="code-badge mitre">ATT&amp;CK: {f.mitre}</span>}
                    {f.confidence !== undefined && (
                      <span className="code-badge confidence">
                        Confidence: {Math.round(f.confidence * 100)}%
                      </span>
                    )}
                  </div>

                  <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                    <button
                      className="btn btn-sm"
                      onClick={() => onOpenAudit(f.site)}
                      title="View complete multi-tab audit report"
                    >
                      Deep-Dive Audit Modal →
                    </button>
                    <a
                      href={f.site.url}
                      target="_blank"
                      rel="noreferrer"
                      className="vuln-target-link"
                    >
                      Inspect Target <Icon name="external" size={11} />
                    </a>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
