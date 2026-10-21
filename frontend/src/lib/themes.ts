export interface Theme {
  name: string;
  swatch: string;
  bg: string; bg2: string; card: string; card2: string;
  border: string; text: string; muted: string;
  low: string; med: string; high: string; crit: string;
  blue: string; violet: string; accent: string;
}

export const THEMES: Theme[] = [
  { name: 'Blue', swatch: '#3B82F6',
    bg: '#F4F8FC', bg2: '#EAF2FA', card: '#FFFFFF', card2: '#E3EEF9',
    border: '#C8DCF0', text: '#1E3A5F', muted: '#6B8FB5',
    low: '#3B82F6', med: '#60A5FA', high: '#2563EB', crit: '#1D4ED8',
    blue: '#0EA5E9', violet: '#6366F1', accent: '#3B82F6' },
  { name: 'Teal', swatch: '#14B8A6',
    bg: '#F0FAFA', bg2: '#E0F4F4', card: '#FFFFFF', card2: '#D5F0F0',
    border: '#B5DEDE', text: '#134E4A', muted: '#5EA8A3',
    low: '#14B8A6', med: '#2DD4BF', high: '#0D9488', crit: '#0F766E',
    blue: '#06B6D4', violet: '#5EEAD4', accent: '#14B8A6' },
  { name: 'Mint Green', swatch: '#22C55E',
    bg: '#F2FBF5', bg2: '#E5F7EC', card: '#FFFFFF', card2: '#D9F2E3',
    border: '#BFE6CF', text: '#14532D', muted: '#6BAF8B',
    low: '#22C55E', med: '#4ADE80', high: '#16A34A', crit: '#15803D',
    blue: '#34D399', violet: '#10B981', accent: '#22C55E' },
  { name: 'Sage', swatch: '#6B9080',
    bg: '#F4F7F2', bg2: '#E9F0E6', card: '#FFFFFF', card2: '#E1EBDC',
    border: '#C5D6BE', text: '#364535', muted: '#8AA283',
    low: '#84A98C', med: '#A8C5A0', high: '#52796F', crit: '#354F52',
    blue: '#6B9080', violet: '#A4C3B2', accent: '#52796F' },
  { name: 'Yellow', swatch: '#EAB308',
    bg: '#FFFCF0', bg2: '#FEF8E0', card: '#FFFFFF', card2: '#FDF2CC',
    border: '#F5E4A8', text: '#713F12', muted: '#B89A4A',
    low: '#EAB308', med: '#FACC15', high: '#CA8A04', crit: '#A16207',
    blue: '#F59E0B', violet: '#D97706', accent: '#EAB308' },
  { name: 'Beige', swatch: '#C4A882',
    bg: '#FAF7F2', bg2: '#F3EDE4', card: '#FFFFFF', card2: '#EDE5D8',
    border: '#D9CDBA', text: '#44403C', muted: '#9C8E7A',
    low: '#C4A882', med: '#D4BC94', high: '#A0845C', crit: '#7C6544',
    blue: '#B8A088', violet: '#8A7560', accent: '#A0845C' },
  { name: 'Brown', swatch: '#8D6E63',
    bg: '#FAF6F3', bg2: '#F2E9E2', card: '#FFFFFF', card2: '#EBDFD4',
    border: '#D4BFA8', text: '#3E2723', muted: '#8D6E63',
    low: '#A1887F', med: '#BCAAA4', high: '#8D6E63', crit: '#5D4037',
    blue: '#795548', violet: '#6D4C41', accent: '#5D4037' },
  { name: 'Orange', swatch: '#F97316',
    bg: '#FFF7F0', bg2: '#FFEDDE', card: '#FFFFFF', card2: '#FFE4CC',
    border: '#F5C9A0', text: '#7C2D12', muted: '#C4845A',
    low: '#F97316', med: '#FB923C', high: '#EA580C', crit: '#C2410C',
    blue: '#F59E0B', violet: '#FB923C', accent: '#EA580C' },
  { name: 'Peach', swatch: '#F5AFAF',
    bg: '#FFF8F8', bg2: '#FEF0F0', card: '#FFFFFF', card2: '#FEEAEA',
    border: '#F2CFCF', text: '#4A3535', muted: '#B08888',
    low: '#D4A0A0', med: '#EBABAB', high: '#E08888', crit: '#C95858',
    blue: '#F5AFAF', violet: '#DE8A8A', accent: '#C95858' },
  { name: 'Red', swatch: '#EF4444',
    bg: '#FFF5F5', bg2: '#FFE8E8', card: '#FFFFFF', card2: '#FFDDDD',
    border: '#F5B8B8', text: '#7F1D1D', muted: '#C47070',
    low: '#F87171', med: '#FCA5A5', high: '#EF4444', crit: '#B91C1C',
    blue: '#DC2626', violet: '#E11D48', accent: '#B91C1C' },
  { name: 'Maroon', swatch: '#9D2E45',
    bg: '#FAF4F5', bg2: '#F2E4E6', card: '#FFFFFF', card2: '#EBD6D9',
    border: '#D4A8AE', text: '#4C0519', muted: '#9F6B73',
    low: '#BE5A6E', med: '#D4738A', high: '#9D2E45', crit: '#6B1024',
    blue: '#A8324A', violet: '#881337', accent: '#6B1024' },
  { name: 'Pink', swatch: '#EC4899',
    bg: '#FDF2F8', bg2: '#FCE7F3', card: '#FFFFFF', card2: '#FBCFE8',
    border: '#F9A8D4', text: '#831843', muted: '#C26A9E',
    low: '#EC4899', med: '#F472B6', high: '#DB2777', crit: '#BE185D',
    blue: '#F9A8D4', violet: '#D946EF', accent: '#BE185D' },
  { name: 'Purple', swatch: '#8B5CF6',
    bg: '#F8F5FF', bg2: '#F1EBFE', card: '#FFFFFF', card2: '#E9E0FC',
    border: '#D4C4F5', text: '#3B0764', muted: '#9B7EC8',
    low: '#A78BFA', med: '#C4B5FD', high: '#8B5CF6', crit: '#6D28D9',
    blue: '#7C3AED', violet: '#A855F7', accent: '#6D28D9' },
  { name: 'Navy', swatch: '#1E3A8A',
    bg: '#0A1628', bg2: '#0F2038', card: '#142844', card2: '#1A3050',
    border: '#243B5C', text: '#E2EAF5', muted: '#8DA4C4',
    low: '#38BDF8', med: '#7DD3FC', high: '#0EA5E9', crit: '#0284C7',
    blue: '#3B82F6', violet: '#6366F1', accent: '#38BDF8' },
  { name: 'Black', swatch: '#171717',
    bg: '#0A0A0A', bg2: '#141414', card: '#1A1A1A', card2: '#222222',
    border: '#2E2E2E', text: '#F5F5F5', muted: '#A0A0A0',
    low: '#737373', med: '#A3A3A3', high: '#D4D4D4', crit: '#E5E5E5',
    blue: '#FAFAFA', violet: '#D4D4D4', accent: '#E5E5E5' },
  { name: 'Grey', swatch: '#737373',
    bg: '#F5F5F5', bg2: '#EBEBEB', card: '#FFFFFF', card2: '#E5E5E5',
    border: '#D4D4D4', text: '#262626', muted: '#737373',
    low: '#A3A3A3', med: '#737373', high: '#525252', crit: '#262626',
    blue: '#404040', violet: '#525252', accent: '#262626' },
  { name: 'White', swatch: '#F5F5F5',
    bg: '#FFFFFF', bg2: '#FAFAFA', card: '#FFFFFF', card2: '#F5F5F5',
    border: '#E5E5E5', text: '#171717', muted: '#737373',
    low: '#A3A3A3', med: '#737373', high: '#404040', crit: '#171717',
    blue: '#262626', violet: '#525252', accent: '#171717' },
];

const STORAGE_KEY = 'nad-theme';

export function applyTheme(t: Theme) {
  const r = document.documentElement.style;
  r.setProperty('--bg', t.bg);
  r.setProperty('--bg2', t.bg2);
  r.setProperty('--card', t.card);
  r.setProperty('--card2', t.card2);
  r.setProperty('--border', t.border);
  r.setProperty('--text', t.text);
  r.setProperty('--muted', t.muted);
  r.setProperty('--low', t.low);
  r.setProperty('--med', t.med);
  r.setProperty('--high', t.high);
  r.setProperty('--crit', t.crit);
  r.setProperty('--blue', t.blue);
  r.setProperty('--violet', t.violet);
  r.setProperty('--accent', t.accent);
  localStorage.setItem(STORAGE_KEY, t.name);
  document.body.style.background = t.bg;
  document.body.style.color = t.text;
}

export function initTheme(): Theme {
  const saved = localStorage.getItem(STORAGE_KEY);
  const t = THEMES.find((x) => x.name === saved) ?? THEMES[8];
  applyTheme(t);
  return t;
}

export function themeByName(name: string): Theme {
  return THEMES.find((x) => x.name === name) ?? THEMES[0];
}
