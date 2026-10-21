import { useEffect, useRef, useState } from 'react';
import { THEMES, applyTheme, type Theme } from '../lib/themes';
import { Icon } from './Icon';

export function ThemePicker({ theme, onChange }: { theme: Theme; onChange: (t: Theme) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey); };
  }, [open]);

  return (
    <div className="theme-picker" ref={ref}>
      <button className="theme-trigger" onClick={() => setOpen(!open)} aria-haspopup="dialog" aria-expanded={open}>
        <span className="trigger-swatch" style={{ background: theme.swatch }} />
        <span className="trigger-name">{theme.name}</span>
        <Icon name="chevron" size={14} className={`trigger-chevron ${open ? 'open' : ''}`} />
      </button>

      {open && (
        <div className="theme-panel" role="dialog" aria-label="Choose theme">
          <div className="theme-panel-title">Appearance</div>
          <div className="theme-cards">
            {THEMES.map((t) => (
              <button
                key={t.name}
                className={`theme-card ${t.name === theme.name ? 'active' : ''}`}
                onClick={() => { applyTheme(t); onChange(t); setOpen(false); }}
              >
                <span className="mini-preview">
                  <span className="mini-bar" style={{ background: t.bg }} />
                  <span className="mini-card" style={{ background: t.card, borderColor: t.border }}>
                    <span className="mini-line" style={{ background: t.text, opacity: .7 }} />
                    <span className="mini-line short" style={{ background: t.muted, opacity: .5 }} />
                    <span className="mini-row">
                      <span className="mini-dot" style={{ background: t.blue }} />
                      <span className="mini-dot" style={{ background: t.violet }} />
                      <span className="mini-dot" style={{ background: t.crit }} />
                    </span>
                  </span>
                </span>
                <span className="theme-card-label">{t.name}</span>
                {t.name === theme.name && <span className="theme-check"><Icon name="check" size={12} /></span>}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
