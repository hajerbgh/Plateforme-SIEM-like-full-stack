import { useState } from 'react';
import { lookupIP } from '../api';
import { Search, Globe, Shield, AlertTriangle } from 'lucide-react';
import '../pages/Dashboard.css';

const PRESETS = ['203.0.113.99', '8.8.8.8', '1.1.1.1', '192.168.1.10'];

export default function IOCLookup() {
  const [ip, setIp]         = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]   = useState('');

  const handleLookup = async (target = ip) => {
    if (!target.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const data = await lookupIP(target.trim());
      if (data?.status === 'success') setResult(data);
      else setError('IP non trouvée ou privée');
    } catch {
      setError('Erreur lors de la requête');
    }
    setLoading(false);
  };

  const isPrivate = (ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">IOC Lookup</h1>
          <p className="page-sub">Réputation d'IP et géolocalisation en temps réel</p>
        </div>
      </div>

      <div className="card" style={{ maxWidth: 640, marginBottom: 16 }}>
        <div style={{ padding: '20px' }}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <div className="search-bar" style={{ flex: 1, margin: 0 }}>
              <Search size={14} style={{ color: 'var(--text3)' }} />
              <input
                placeholder="Entrer une adresse IP (ex: 203.0.113.1)"
                value={ip}
                onChange={e => setIp(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleLookup()}
              />
            </div>
            <button className="btn-primary" onClick={() => handleLookup()} disabled={loading}>
              {loading ? 'Recherche...' : 'Analyser'}
            </button>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, color: 'var(--text3)' }}>Exemples :</span>
            {PRESETS.map(p => (
              <button key={p} onClick={() => { setIp(p); handleLookup(p); }}
                style={{ fontFamily: 'var(--mono)', fontSize: 11, padding: '2px 8px', border: '1px solid var(--border)', borderRadius: 4, background: 'var(--surface2)', color: 'var(--text2)', cursor: 'pointer' }}>
                {p}
              </button>
            ))}
          </div>
        </div>
      </div>

      {error && (
        <div style={{ background: 'var(--critical-bg)', border: '1px solid #FCA5A5', borderRadius: 'var(--radius)', padding: '12px 16px', fontSize: 13, color: 'var(--critical)', maxWidth: 640 }}>
          {error}
        </div>
      )}

      {result && (
        <div className="card" style={{ maxWidth: 640 }}>
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Globe size={16} style={{ color: 'var(--accent)' }} />
            <h2 className="card-title" style={{ fontFamily: 'var(--mono)' }}>{result.query}</h2>
            {(result.proxy || result.hosting) && (
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--high)', background: 'var(--high-bg)', padding: '2px 8px', borderRadius: 99, fontWeight: 600 }}>
                <AlertTriangle size={11} />
                {result.proxy ? 'Proxy/VPN' : 'Hébergement'}
              </span>
            )}
            {isPrivate(result.query) && (
              <span style={{ fontSize: 11, color: 'var(--low)', background: 'var(--low-bg)', padding: '2px 8px', borderRadius: 99, fontWeight: 600 }}>
                IP Privée
              </span>
            )}
          </div>
          <div style={{ padding: '16px 20px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            {[
              ['Pays',         result.country],
              ['Région',       result.regionName],
              ['Ville',        result.city],
              ['ISP',          result.isp],
              ['Organisation', result.org],
              ['AS',           result.as],
              ['Mobile',       result.mobile ? 'Oui' : 'Non'],
              ['Proxy/VPN',    result.proxy ? 'Détecté' : 'Non'],
            ].map(([label, value]) => (
              <div key={label} style={{ background: 'var(--surface2)', borderRadius: 'var(--radius)', padding: '10px 12px' }}>
                <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 3 }}>{label}</div>
                <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text1)' }}>{value || '—'}</div>
              </div>
            ))}
          </div>

          <div style={{ padding: '0 20px 16px' }}>
            <div style={{ background: result.proxy || result.hosting ? 'var(--high-bg)' : 'var(--low-bg)', border: `1px solid ${result.proxy || result.hosting ? '#FDE68A' : '#A7F3D0'}`, borderRadius: 'var(--radius)', padding: '10px 14px', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Shield size={14} style={{ color: result.proxy || result.hosting ? 'var(--high)' : 'var(--low)' }} />
              <span style={{ fontSize: 12, color: result.proxy || result.hosting ? 'var(--high)' : 'var(--low)', fontWeight: 500 }}>
                {result.proxy ? 'Trafic potentiellement masqué (proxy/VPN détecté)' :
                 result.hosting ? 'IP d\'hébergement — potentiellement un serveur C2' :
                 'Aucun indicateur de proxy ou d\'hébergement suspect'}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
