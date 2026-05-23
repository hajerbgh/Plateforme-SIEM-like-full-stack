import { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { getStats, simulateLogs } from '../api';
import { AlertTriangle, Activity, ShieldAlert, CheckCircle, RefreshCw } from 'lucide-react';
import './Dashboard.css';

const SEV_COLORS = { CRITICAL: '#DC2626', HIGH: '#EA580C', MEDIUM: '#D97706', LOW: '#059669' };

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);

  const load = async () => {
    setLoading(true);
    try { const r = await getStats(); setStats(r.data); } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleSimulate = async () => {
    setSimulating(true);
    try { await simulateLogs(); await load(); } catch {}
    setSimulating(false);
  };

  const sevData = stats ? Object.entries(stats.alerts_by_severity).map(([k, v]) => ({ name: k, value: v })) : [];

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-sub">Vue d'ensemble de la sécurité en temps réel</p>
        </div>
        <button className={`btn-primary ${simulating ? 'loading' : ''}`} onClick={handleSimulate} disabled={simulating}>
          <RefreshCw size={14} className={simulating ? 'spin' : ''} />
          {simulating ? 'Simulation...' : 'Simuler des attaques'}
        </button>
      </div>

      {loading ? (
        <div className="loading-state">Chargement...</div>
      ) : stats ? (
        <>
          <div className="stat-grid">
            <StatCard icon={<Activity size={18} />} label="Logs ingérés" value={stats.total_logs} color="accent" />
            <StatCard icon={<AlertTriangle size={18} />} label="Total alertes" value={stats.total_alerts} color="medium" />
            <StatCard icon={<ShieldAlert size={18} />} label="Alertes ouvertes" value={stats.open_alerts} color="high" />
            <StatCard icon={<CheckCircle size={18} />} label="Critiques" value={stats.critical_alerts} color="critical" />
          </div>

          <div className="dashboard-grid">
            <div className="card">
              <div className="card-header">
                <h2 className="card-title">Alertes par sévérité</h2>
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={sevData} barSize={36}>
                  <XAxis dataKey="name" tick={{ fontSize: 12, fontFamily: 'DM Sans' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 12, fontFamily: 'DM Sans' }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ fontFamily: 'DM Sans', fontSize: 12, borderRadius: 8, border: '1px solid #E2E5EB' }} />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {sevData.map((entry) => (
                      <Cell key={entry.name} fill={SEV_COLORS[entry.name] || '#8A94A6'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="card">
              <div className="card-header">
                <h2 className="card-title">Top IPs suspectes</h2>
              </div>
              {stats.top_source_ips.length === 0 ? (
                <div className="empty-state">Aucune donnée</div>
              ) : (
                <div className="ip-list">
                  {stats.top_source_ips.map((item, i) => (
                    <div key={item.ip} className="ip-row">
                      <span className="ip-rank">{i + 1}</span>
                      <code className="ip-addr">{item.ip}</code>
                      <div className="ip-bar-wrap">
                        <div className="ip-bar" style={{ width: `${Math.min(100, item.count * 20)}%` }} />
                      </div>
                      <span className="ip-count">{item.count} alertes</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="card mitre-card">
              <div className="card-header">
                <h2 className="card-title">MITRE ATT&CK — Couverture</h2>
              </div>
              <div className="mitre-grid">
                {[
                  { id: 'T1110', tactic: 'Credential Access', name: 'Brute Force',       color: '#DC2626' },
                  { id: 'T1046', tactic: 'Discovery',         name: 'Port Scan',          color: '#EA580C' },
                  { id: 'T1190', tactic: 'Initial Access',    name: 'Exploit Public App', color: '#D97706' },
                  { id: 'T1059', tactic: 'Execution',         name: 'Command & Script',   color: '#7C3AED' },
                  { id: 'T1003', tactic: 'Credential Access', name: 'OS Credential',      color: '#0057FF' },
                  { id: 'ML',    tactic: 'Unknown / Zero-Day','name': 'ML Detected',      color: '#059669' },
                ].map(t => (
                  <div key={t.id} className="mitre-cell" style={{ '--tc': t.color }}>
                    <div className="mitre-id">{t.id}</div>
                    <div className="mitre-name">{t.name}</div>
                    <div className="mitre-tactic">{t.tactic}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      ) : (
        <div className="empty-state">Backend non disponible — Lance uvicorn app.main:app --reload</div>
      )}
    </div>
  );
}

function StatCard({ icon, label, value, color }) {
  return (
    <div className={`stat-card stat-${color}`}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-value">{value ?? '—'}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
