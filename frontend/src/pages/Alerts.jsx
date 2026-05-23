import { useEffect, useState } from 'react';
import { getAlerts, updateAlert } from '../api';
import SeverityBadge from '../components/SeverityBadge';
import { ChevronDown, Filter, RefreshCw } from 'lucide-react';
import './Alerts.css';

const STATUS_LABELS = {
  OPEN: { label: 'Ouverte', color: '#DC2626', bg: '#FEF2F2' },
  INVESTIGATING: { label: 'En cours', color: '#D97706', bg: '#FFFBEB' },
  RESOLVED: { label: 'Résolue', color: '#059669', bg: '#ECFDF5' },
  FALSE_POSITIVE: { label: 'Faux positif', color: '#8A94A6', bg: '#F7F8FA' },
};

export default function Alerts() {
  const [alerts, setAlerts]     = useState([]);
  const [loading, setLoading]   = useState(true);
  const [selected, setSelected] = useState(null);
  const [filter, setFilter]     = useState({ status: '', severity: '' });
  const [notes, setNotes]       = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const params = {};
      if (filter.status)   params.status   = filter.status;
      if (filter.severity) params.severity = filter.severity;
      const r = await getAlerts(params);
      setAlerts(r.data);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, [filter]);

  const handleSelect = (a) => {
    setSelected(a);
    setNotes(a.analyst_notes || '');
  };

  const handleUpdate = async (id, status) => {
    try {
      await updateAlert(id, { status, analyst_notes: notes });
      await load();
      setSelected(prev => prev ? { ...prev, status, analyst_notes: notes } : null);
    } catch {}
  };

  const fmt = (ts) => new Date(ts).toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });

  return (
    <div className="alerts-layout">
      <div className="alerts-list-panel">
        <div className="panel-header">
          <div>
            <h1 className="page-title">Alertes</h1>
            <p className="page-sub">{alerts.length} alerte(s) trouvée(s)</p>
          </div>
          <button className="icon-btn" onClick={load}><RefreshCw size={14} /></button>
        </div>

        <div className="filter-bar">
          <Filter size={13} style={{ color: 'var(--text3)' }} />
          <select value={filter.status} onChange={e => setFilter(f => ({ ...f, status: e.target.value }))}>
            <option value="">Tous statuts</option>
            <option value="OPEN">Ouverte</option>
            <option value="INVESTIGATING">En cours</option>
            <option value="RESOLVED">Résolue</option>
            <option value="FALSE_POSITIVE">Faux positif</option>
          </select>
          <select value={filter.severity} onChange={e => setFilter(f => ({ ...f, severity: e.target.value }))}>
            <option value="">Toutes sévérités</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        <div className="alerts-table">
          <div className="table-head">
            <span>Sévérité</span>
            <span>Titre</span>
            <span>IP Source</span>
            <span>Statut</span>
            <span>Heure</span>
          </div>
          {loading ? (
            <div className="empty-state">Chargement...</div>
          ) : alerts.length === 0 ? (
            <div className="empty-state">Aucune alerte — lance une simulation depuis le Dashboard</div>
          ) : (
            alerts.map(a => {
              const st = STATUS_LABELS[a.status] || STATUS_LABELS.OPEN;
              return (
                <div key={a.id} className={`table-row ${selected?.id === a.id ? 'selected' : ''}`} onClick={() => handleSelect(a)}>
                  <span><SeverityBadge severity={a.severity} /></span>
                  <span className="alert-title">{a.title}</span>
                  <code className="ip-mono">{a.source_ip || '—'}</code>
                  <span>
                    <span className="status-pill" style={{ color: st.color, background: st.bg }}>{st.label}</span>
                  </span>
                  <span className="time-text">{fmt(a.created_at)}</span>
                </div>
              );
            })
          )}
        </div>
      </div>

      {selected && (
        <div className="alert-detail-panel">
          <div className="detail-header">
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <SeverityBadge severity={selected.severity} />
                {selected.mitre_technique && (
                  <span className="mitre-tag">{selected.mitre_technique}</span>
                )}
              </div>
              <h2 className="detail-title">{selected.title}</h2>
            </div>
          </div>

          <div className="detail-body">
            <Section label="Description">
              <p style={{ fontSize: 13, color: 'var(--text2)', lineHeight: 1.7 }}>{selected.description}</p>
            </Section>

            <Section label="Informations">
              <div className="info-grid">
                <InfoRow label="Règle"       value={selected.rule_name} />
                <InfoRow label="IP Source"   value={<code className="ip-mono">{selected.source_ip || '—'}</code>} />
                <InfoRow label="Tactique"    value={selected.mitre_tactic || '—'} />
                <InfoRow label="Technique"   value={selected.mitre_technique || '—'} />
                <InfoRow label="Créée le"    value={new Date(selected.created_at).toLocaleString('fr-FR')} />
              </div>
            </Section>

            <Section label="Notes d'analyse">
              <textarea
                className="notes-area"
                placeholder="Observations, contexte, actions prises..."
                value={notes}
                onChange={e => setNotes(e.target.value)}
                rows={4}
              />
            </Section>

            <Section label="Actions">
              <div className="action-btns">
                <button className="action-btn investigating" onClick={() => handleUpdate(selected.id, 'INVESTIGATING')}>
                  En investigation
                </button>
                <button className="action-btn resolved" onClick={() => handleUpdate(selected.id, 'RESOLVED')}>
                  Marquer résolue
                </button>
                <button className="action-btn false-pos" onClick={() => handleUpdate(selected.id, 'FALSE_POSITIVE')}>
                  Faux positif
                </button>
              </div>
            </Section>
          </div>
        </div>
      )}
    </div>
  );
}

function Section({ label, children }) {
  return (
    <div className="detail-section">
      <div className="section-label">{label}</div>
      {children}
    </div>
  );
}

function InfoRow({ label, value }) {
  return (
    <div className="info-row">
      <span className="info-label">{label}</span>
      <span className="info-value">{value}</span>
    </div>
  );
}
