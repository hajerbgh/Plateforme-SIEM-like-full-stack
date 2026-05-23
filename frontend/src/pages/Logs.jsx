import { useEffect, useState } from 'react';
import { getLogs } from '../api';
import { RefreshCw, Search } from 'lucide-react';
import './Logs.css';

export default function Logs() {
  const [logs, setLogs]       = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch]   = useState('');

  const load = async () => {
    setLoading(true);
    try { const r = await getLogs({ limit: 100 }); setLogs(r.data); } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const filtered = logs.filter(l =>
    !search || l.source_ip?.includes(search) || l.event_type?.includes(search) || l.message?.toLowerCase().includes(search.toLowerCase())
  );

  const fmt = (ts) => new Date(ts).toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });

  const eventColor = (t) => ({
    login_failed: '#DC2626', port_scan: '#EA580C', command_exec: '#7C3AED',
    login_success: '#059669', http_request: '#0057FF', dns_query: '#8A94A6',
  }[t] || '#8A94A6');

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Logs</h1>
          <p className="page-sub">{filtered.length} événements</p>
        </div>
        <button className="icon-btn" onClick={load}><RefreshCw size={14} /></button>
      </div>

      <div className="search-bar">
        <Search size={13} style={{ color: 'var(--text3)' }} />
        <input placeholder="Rechercher par IP, type, message..." value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      <div className="logs-table card">
        <div className="logs-head">
          <span>Timestamp</span>
          <span>IP Source</span>
          <span>Type</span>
          <span>Port</span>
          <span>Message</span>
        </div>
        <div className="logs-body">
          {loading ? (
            <div className="empty-state">Chargement...</div>
          ) : filtered.length === 0 ? (
            <div className="empty-state">Aucun log — lance une simulation depuis le Dashboard</div>
          ) : filtered.map(l => (
            <div key={l.id} className="log-row">
              <code className="log-ts">{fmt(l.timestamp)}</code>
              <code className="ip-mono">{l.source_ip}</code>
              <span className="event-tag" style={{ '--ec': eventColor(l.event_type) }}>{l.event_type}</span>
              <code className="log-port">{l.dest_port || '—'}</code>
              <span className="log-msg">{l.message}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
