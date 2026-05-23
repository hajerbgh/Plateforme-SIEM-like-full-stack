import { useState, useEffect } from 'react';
import { mlStatus, trainML, seedData, predictLog } from '../api';
import { Brain, CheckCircle, AlertCircle } from 'lucide-react';
import '../pages/Dashboard.css';

export default function MLDetector() {
  const [status, setStatus]   = useState(null);
  const [trainRes, setTrainRes] = useState(null);
  const [loading, setLoading] = useState('');
  const [form, setForm]       = useState({ source_ip: '203.0.113.99', dest_port: 31337, protocol: 'TCP', event_type: 'port_scan', message: 'SYN scan on unusual port' });
  const [prediction, setPrediction] = useState(null);

  useEffect(() => { mlStatus().then(r => setStatus(r.data)).catch(() => {}); }, []);

  const handleSeed = async () => {
    setLoading('seed');
    try { const r = await seedData(); alert(`${r.data.total} logs injectés`); } catch {}
    setLoading('');
  };

  const handleTrain = async () => {
    setLoading('train');
    try { const r = await trainML(); setTrainRes(r.data); await mlStatus().then(r => setStatus(r.data)); } catch {}
    setLoading('');
  };

  const handlePredict = async () => {
    setLoading('predict');
    try { const r = await predictLog({ ...form, dest_port: parseInt(form.dest_port) }); setPrediction(r.data); } catch {}
    setLoading('');
  };

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">ML Detector</h1>
          <p className="page-sub">Isolation Forest — détection d'anomalies non supervisée</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {status && (
            <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: status.trained ? 'var(--low)' : 'var(--text3)' }}>
              {status.trained ? <CheckCircle size={14} /> : <AlertCircle size={14} />}
              {status.trained ? 'Modèle entraîné' : 'Modèle non entraîné'}
            </span>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="card">
          <div className="card-header"><h2 className="card-title">Entraînement</h2></div>
          <div style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <p style={{ fontSize: 13, color: 'var(--text2)', lineHeight: 1.7 }}>
              1. Injecter des données d'entraînement réalistes (200 logs normaux + 5 anomalies)<br/>
              2. Entraîner Isolation Forest sur ces données
            </p>
            <button className="btn-primary" onClick={handleSeed} disabled={loading === 'seed'} style={{ width: 'fit-content' }}>
              {loading === 'seed' ? 'Injection...' : '1. Générer les données'}
            </button>
            <button className="btn-primary" onClick={handleTrain} disabled={loading === 'train'} style={{ width: 'fit-content', background: 'var(--low)' }}>
              {loading === 'train' ? 'Entraînement...' : '2. Entraîner le modèle'}
            </button>
            {trainRes && (
              <div style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '12px 14px', fontSize: 12 }}>
                <div style={{ fontWeight: 600, marginBottom: 6, color: 'var(--low)' }}>Entraînement terminé</div>
                <div>Logs utilisés : <strong>{trainRes.logs_used}</strong></div>
                <div>Anomalies détectées : <strong>{trainRes.n_anomalies_found}</strong> ({trainRes.anomaly_rate}%)</div>
                <div>Score moyen : <strong>{trainRes.score_mean}</strong></div>
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header"><h2 className="card-title">Tester un log</h2></div>
          <div style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[
              ['source_ip', 'IP Source'],
              ['dest_port', 'Port destination'],
              ['protocol', 'Protocole'],
              ['event_type', 'Type d\'événement'],
              ['message', 'Message'],
            ].map(([key, label]) => (
              <div key={key}>
                <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 3 }}>{label}</label>
                <input
                  value={form[key]}
                  onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                  style={{ width: '100%', padding: '7px 10px', border: '1px solid var(--border)', borderRadius: 'var(--radius)', fontSize: 13, background: 'var(--surface2)' }}
                />
              </div>
            ))}
            <button className="btn-primary" onClick={handlePredict} disabled={loading === 'predict'} style={{ marginTop: 4 }}>
              {loading === 'predict' ? 'Analyse...' : 'Analyser ce log'}
            </button>
            {prediction && (
              <div style={{
                background: prediction.is_anomaly ? 'var(--critical-bg)' : 'var(--low-bg)',
                border: `1px solid ${prediction.is_anomaly ? '#FCA5A5' : '#A7F3D0'}`,
                borderRadius: 'var(--radius)', padding: '12px 14px', fontSize: 12,
              }}>
                <div style={{ fontWeight: 700, fontSize: 14, color: prediction.is_anomaly ? 'var(--critical)' : 'var(--low)', marginBottom: 6 }}>
                  {prediction.verdict}
                </div>
                <div>Score : <code style={{ fontFamily: 'var(--mono)' }}>{prediction.score}</code></div>
                {prediction.is_anomaly && <div>Sévérité : <strong>{prediction.severity}</strong></div>}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
