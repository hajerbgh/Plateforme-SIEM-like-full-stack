import { useEffect, useState } from 'react';
import { getRules, toggleRule, seedRules } from '../api';
import SeverityBadge from '../components/SeverityBadge';
import { ToggleLeft, ToggleRight, RefreshCw } from 'lucide-react';
import '../pages/Dashboard.css';

export default function Rules() {
  const [rules, setRules]     = useState([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try { const r = await getRules(); setRules(r.data); } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleToggle = async (id) => {
    try { await toggleRule(id); await load(); } catch {}
  };

  const handleSeed = async () => {
    try { await seedRules(); await load(); } catch {}
  };

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Règles de détection</h1>
          <p className="page-sub">{rules.length} règles configurées</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="icon-btn" onClick={load}><RefreshCw size={14} /></button>
          <button className="btn-primary" onClick={handleSeed}>Charger règles par défaut</button>
        </div>
      </div>

      <div className="card">
        <div className="table-head" style={{ gridTemplateColumns: '1fr 160px 160px 120px 80px' }}>
          <span>Nom / Description</span>
          <span>Sévérité</span>
          <span>MITRE Technique</span>
          <span>Condition</span>
          <span>Actif</span>
        </div>
        {loading ? (
          <div className="empty-state">Chargement...</div>
        ) : rules.map(r => (
          <div key={r.id} className="table-row" style={{ gridTemplateColumns: '1fr 160px 160px 120px 80px' }}>
            <div>
              <div style={{ fontWeight: 500, fontSize: 13, color: 'var(--text1)' }}>{r.name}</div>
              <div style={{ fontSize: 12, color: 'var(--text3)', marginTop: 2 }}>{r.description}</div>
            </div>
            <span><SeverityBadge severity={r.severity} /></span>
            <span>
              {r.mitre_technique ? (
                <span style={{ fontFamily: 'var(--mono)', fontSize: 11, background: '#EEF3FF', color: '#0057FF', padding: '2px 7px', borderRadius: 4 }}>
                  {r.mitre_technique}
                </span>
              ) : '—'}
            </span>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text3)' }}>{r.condition}</span>
            <span>
              <button onClick={() => handleToggle(r.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: r.enabled ? 'var(--low)' : 'var(--text3)' }}>
                {r.enabled ? <ToggleRight size={22} /> : <ToggleLeft size={22} />}
              </button>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
