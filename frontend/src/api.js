import axios from 'axios';

const api = axios.create({ baseURL: 'http://localhost:8000/api' });

export const getStats       = ()          => api.get('/alerts/stats');
export const getAlerts      = (params)    => api.get('/alerts', { params });
export const updateAlert    = (id, data)  => api.patch(`/alerts/${id}`, data);
export const getLogs        = (params)    => api.get('/logs', { params });
export const simulateLogs   = ()          => api.get('/logs/simulate');
export const getRules       = ()          => api.get('/rules');
export const toggleRule     = (id)        => api.patch(`/rules/${id}/toggle`);
export const trainML        = ()          => api.post('/ml/train');
export const mlStatus       = ()          => api.get('/ml/status');
export const seedData       = ()          => api.post('/ml/seed-data');
export const seedRules      = ()          => api.post('/rules/seed');
export const predictLog     = (data)      => api.post('/ml/predict', data);

// IOC Lookup — AbuseIPDB (public demo endpoint)
export const lookupIP = async (ip) => {
  // On utilise une API publique de réputation IP gratuite
  try {
    const r = await axios.get(`https://ip-api.com/json/${ip}?fields=status,country,regionName,city,isp,org,as,query,mobile,proxy,hosting`);
    return r.data;
  } catch {
    return null;
  }
};
