import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Bell, ScrollText, Shield, Brain, Search, ChevronRight } from 'lucide-react';
import './Sidebar.css';

const nav = [
  { to: '/',        icon: LayoutDashboard, label: 'Dashboard'   },
  { to: '/alerts',  icon: Bell,            label: 'Alertes'     },
  { to: '/logs',    icon: ScrollText,      label: 'Logs'        },
  { to: '/rules',   icon: Shield,          label: 'Règles'      },
  { to: '/ml',      icon: Brain,           label: 'ML Detector' },
  { to: '/ioc',     icon: Search,          label: 'IOC Lookup'  },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-mark">TV</div>
        <div>
          <div className="logo-name">ThreatVision</div>
          <div className="logo-sub">SOC Platform</div>
        </div>
      </div>

      <div className="sidebar-section-label">Navigation</div>
      <nav className="sidebar-nav">
        {nav.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <Icon size={16} />
            <span>{label}</span>
            <ChevronRight size={12} className="nav-arrow" />
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="status-dot" />
        <span>Backend connecté</span>
      </div>
    </aside>
  );
}
