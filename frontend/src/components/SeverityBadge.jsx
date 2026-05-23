export default function SeverityBadge({ severity }) {
  const map = {
    CRITICAL: { label: 'Critical', color: 'var(--critical)', bg: 'var(--critical-bg)' },
    HIGH:     { label: 'High',     color: 'var(--high)',     bg: 'var(--high-bg)'     },
    MEDIUM:   { label: 'Medium',   color: 'var(--medium)',   bg: 'var(--medium-bg)'   },
    LOW:      { label: 'Low',      color: 'var(--low)',      bg: 'var(--low-bg)'      },
  };
  const s = map[severity] || map.LOW;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px', borderRadius: 99,
      fontSize: 11, fontWeight: 600,
      color: s.color, background: s.bg,
    }}>
      <span style={{ width: 5, height: 5, borderRadius: '50%', background: s.color, display: 'inline-block' }} />
      {s.label}
    </span>
  );
}
