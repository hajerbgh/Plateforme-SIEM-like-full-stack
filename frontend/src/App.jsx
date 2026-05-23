import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Sidebar    from './components/Sidebar';
import Dashboard  from './pages/Dashboard';
import Alerts     from './pages/Alerts';
import Logs       from './pages/Logs';
import Rules      from './pages/Rules';
import MLDetector from './pages/MLDetector';
import IOCLookup  from './pages/IOCLookup';
import './App.css';

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar />
        <main className="app-main">
          <Routes>
            <Route path="/"       element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/logs"   element={<Logs />} />
            <Route path="/rules"  element={<Rules />} />
            <Route path="/ml"     element={<MLDetector />} />
            <Route path="/ioc"    element={<IOCLookup />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
