import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

export default function Sidebar() {
  const navigate = useNavigate();
  const location = useLocation();

  const menuItems = [
    { icon: '🏠', label: 'Dashboard', path: '/dashboard' },
    { icon: '💻', label: 'Asset Inventory', path: '/assets' },
    { icon: '🔍', label: 'Scan Management', path: '/scans' },
    { icon: '⚠️', label: 'Vulnerabilities', path: '/vulnerabilities' },
    { icon: '📊', label: 'Reports Hub', path: '/reports' },
    { icon: '⚙️', label: 'Settings', path: '/settings' },
  ];

  const isActive = (path) => location.pathname === path;

  return (
    <div style={{
      width: 240,
      background: 'linear-gradient(180deg, #0a1929 0%, #001e3c 100%)',
      height: '100vh',
      position: 'fixed',
      left: 0,
      top: 0,
      borderRight: '1px solid rgba(0, 229, 255, 0.2)',
      display: 'flex',
      flexDirection: 'column',
      zIndex: 1000
    }}>
      {/* Logo */}
      <div style={{
        padding: '30px 20px',
        borderBottom: '1px solid rgba(0, 229, 255, 0.15)',
        display: 'flex',
        alignItems: 'center',
        gap: 15
      }}>
        <div style={{
          width: 45,
          height: 45,
          background: 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
          borderRadius: 10,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 24,
          boxShadow: '0 4px 15px rgba(0, 229, 255, 0.4)'
        }}>
          🛡️
        </div>
        <div>
          <h2 style={{
            margin: 0,
            fontSize: 20,
            fontWeight: 700,
            background: 'linear-gradient(90deg, #00e5ff 0%, #fff 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>
            Aegis
          </h2>
          <p style={{ margin: 0, fontSize: 11, color: '#64b5f6' }}>Security Platform</p>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: '20px 0', overflowY: 'auto' }}>
        {menuItems.map((item, idx) => (
          <div
            key={idx}
            onClick={() => navigate(item.path)}
            style={{
              padding: '14px 20px',
              margin: '4px 10px',
              borderRadius: 10,
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              cursor: 'pointer',
              background: isActive(item.path)
                ? 'linear-gradient(90deg, rgba(0, 229, 255, 0.15) 0%, rgba(0, 145, 234, 0.1) 100%)'
                : 'transparent',
              borderLeft: isActive(item.path) ? '3px solid #00e5ff' : '3px solid transparent',
              transition: 'all 0.3s ease',
              position: 'relative',
              overflow: 'hidden'
            }}
            onMouseEnter={(e) => {
              if (!isActive(item.path)) {
                e.currentTarget.style.background = 'rgba(0, 229, 255, 0.05)';
              }
            }}
            onMouseLeave={(e) => {
              if (!isActive(item.path)) {
                e.currentTarget.style.background = 'transparent';
              }
            }}
          >
            <span style={{ fontSize: 20 }}>{item.icon}</span>
            <span style={{
              fontSize: 14,
              fontWeight: isActive(item.path) ? 600 : 400,
              color: isActive(item.path) ? '#00e5ff' : '#b0bec5'
            }}>
              {item.label}
            </span>
          </div>
        ))}

        {/* Help Button - New Addition */}
        <div
          onClick={() => window.open('/user-guide.md', '_blank')}
          style={{
            padding: '14px 20px',
            margin: '15px 10px 10px 10px',
            borderRadius: 10,
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            cursor: 'pointer',
            background: 'rgba(0, 229, 255, 0.08)',
            border: '1px dashed rgba(0, 229, 255, 0.3)',
            transition: 'all 0.3s ease'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'rgba(0, 229, 255, 0.15)';
            e.currentTarget.style.borderColor = 'rgba(0, 229, 255, 0.5)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'rgba(0, 229, 255, 0.08)';
            e.currentTarget.style.borderColor = 'rgba(0, 229, 255, 0.3)';
          }}
        >
          <span style={{ fontSize: 20 }}>❓</span>
          <span style={{
            fontSize: 14,
            fontWeight: 500,
            color: '#90caf9'
          }}>
            Help & Guide
          </span>
        </div>
      </nav>

      {/* User Profile */}
      <div style={{
        padding: 20,
        borderTop: '1px solid rgba(0, 229, 255, 0.15)',
        display: 'flex',
        alignItems: 'center',
        gap: 12
      }}>
        <div style={{
          width: 36,
          height: 36,
          borderRadius: '50%',
          background: 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 14,
          fontWeight: 700,
          color: '#001e3c'
        }}>
          AM
        </div>
        <div style={{ flex: 1 }}>
          <p style={{ margin: 0, fontSize: 13, fontWeight: 600, color: '#fff' }}>Admin</p>
          <p style={{ margin: 0, fontSize: 11, color: '#64b5f6' }}>Administrator</p>
        </div>
      </div>
    </div>
  );
}
