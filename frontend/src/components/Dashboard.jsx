// src/components/ModernDashboard.jsx
import React, { useEffect, useState, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import api from '../services/api';
import { initSocket } from '../services/socket';
import Sidebar from './Sidebar';

export default function ModernDashboard() {
  const [vms, setVms] = useState([]);
  const [summary, setSummary] = useState({});
  const [recentScans, setRecentScans] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [scanning, setScanning] = useState(false);
  const [showDiscovery, setShowDiscovery] = useState(false);
  const [networkRange, setNetworkRange] = useState('192.168.1.0/24');
  const [discovering, setDiscovering] = useState(false);

  // Scan mode + modal
  const [scanMode, setScanMode] = useState('fast');
  const [showScanModal, setShowScanModal] = useState(false);
  const [selectedVM, setSelectedVM] = useState(null);

  // Clock
  const [currentTime, setCurrentTime] = useState(new Date());

  const { user, logout } = useContext(AuthContext);
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    loadData();

    const socket = initSocket();
    const onScanUpdate = (data) => {
      // Update corresponding scan in recentScans
      setRecentScans(prevScans =>
        prevScans.map(scan =>
          scan.id === data.scan_id
            ? { ...scan, status: data.status, progress: data.progress, phase: data.phase, eta: data.eta ?? scan.eta }
            : scan
        )
      );

      // If finished/failed refresh after a short delay
      if (data.status === 'completed' || data.status === 'failed') {
        setTimeout(loadData, 1000);
      }
    };

    if (socket) {
      socket.on('scan_update', onScanUpdate);
    }

    return () => {
      if (socket) {
        socket.off('scan_update', onScanUpdate);
        // don't force disconnect if other parts of app may share socket; safe to call if exclusive
        if (typeof socket.disconnect === 'function') socket.disconnect();
      }
    };
    // intentionally run once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadData = async () => {
    // VMs
    try {
      const res = await api.get('/api/vms');
      const serverData = res.data;
      const arr = Array.isArray(serverData?.vms) ? serverData.vms : (Array.isArray(serverData) ? serverData : []);
      const mapped = arr.map(vm => ({
        id: vm.id,
        name: vm.name || vm.hostname || vm.host || vm.display_name || `vm-${vm.id}`,
        ip: vm.ip || vm.ip_address || vm.address || vm.host || '',
        os: vm.os || vm.operating_system || 'Unknown'
      }));
      setVms(mapped);
    } catch (err) {
      console.error('Failed loading VMs', err);
      setVms([]);
    }

    // Summary
    api.get('/api/summary')
      .then(res => setSummary(res.data || {}))
      .catch(err => console.error('summary error', err));

    // Recent scans
    api.get('/api/scans/recent')
      .then(res => {
        const items = Array.isArray(res.data) ? res.data : (res.data?.items || []);
        const normalized = items.map(s => ({
          id: s.id,
          target: s.target,
          status: s.status,
          progress: s.progress ?? 0,
          phase: s.phase,
          eta: s.eta,
          startTime: s.startTime || s.start_time || s.start_time
        }));
        setRecentScans(normalized);
      })
      .catch(err => {
        console.error('scans/recent error', err);
        setRecentScans([]);
      });

    // Vulnerabilities by severity
    api.get('/api/vulnerabilities/by-severity')
      .then(res => setVulnerabilities(res.data || { critical: 0, high: 0, medium: 0, low: 0 }))
      .catch(err => console.error('vuln severity error', err));
  };

  // Discovery
  const handleDiscoverVMs = async () => {
    setDiscovering(true);
    try {
      const { data } = await api.post('/api/vm/discover', { network: networkRange });
      alert(`✅ ${data.message}\n\nFound ${data.total_up || 0} live hosts, added ${data.discovered?.length || 0} new VMs.`);
      await loadData();
      setShowDiscovery(false);
    } catch (err) {
      console.error(err);
      alert('Discovery failed: ' + (err.response?.data?.error || err.message || 'Unknown error') + '\n\nMake sure nmap is installed on the server.');
    } finally {
      setDiscovering(false);
    }
  };

  // Start scan (called from modal)
  const handleScan = async (vm, mode = scanMode) => {
    setScanning(true);
    try {
      const { data } = await api.post('/api/scan/start', { target: vm.ip, mode: mode });
      const eta = data.eta || 'Unknown';
      alert(`${mode.toUpperCase()} scan started! Scan ID: ${data.scan_id}\nEstimated time: ${eta}`);
      // Optimistically add a queued scan to the UI
      setRecentScans(prev => [{ id: data.scan_id, target: vm.ip, status: 'queued', progress: 0, phase: 'queued', eta }, ...prev]);
      setTimeout(loadData, 2000);
      setShowScanModal(false);
    } catch (err) {
      console.error(err);
      alert('Scan failed: ' + (err.response?.data?.error || err.message || 'Unknown error'));
    } finally {
      setScanning(false);
    }
  };

  const totalVulns = (vulnerabilities.critical || 0) + (vulnerabilities.high || 0) + (vulnerabilities.medium || 0) + (vulnerabilities.low || 0);
  const riskScore = Math.min(100, Math.round(
    ((vulnerabilities.critical || 0) * 10 + (vulnerabilities.high || 0) * 5 + (vulnerabilities.medium || 0) * 2 + (vulnerabilities.low || 0)) / Math.max(1, totalVulns) * 10
  ));

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#0a1929' }}>
      <Sidebar />

      {/* Main Content */}
      <div style={{ marginLeft: 240, flex: 1, padding: 40 }}>
        {/* Header */}
        <div style={{ marginBottom: 40, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h1 style={{
              margin: 0,
              fontSize: 32,
              fontWeight: 700,
              background: 'linear-gradient(90deg, #00e5ff 0%, #fff 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent'
            }}>
              Main Dashboard
            </h1>
            <p style={{ margin: '5px 0 0 0', color: '#64b5f6', fontSize: 14 }}>
              Welcome back, {user?.username}
            </p>
            <p style={{ margin: '3px 0 0 0', color: '#90caf9', fontSize: 12 }}>
              🕒 {currentTime.toLocaleString('en-IN', {
                timeZone: 'Asia/Kolkata',
                dateStyle: 'full',
                timeStyle: 'medium'
              })}
            </p>
          </div>

          <div style={{ display: 'flex', gap: 15, alignItems: 'center' }}>
            <button
              onClick={() => setShowDiscovery(!showDiscovery)}
              style={{
                padding: '12px 24px',
                background: 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
                color: '#001e3c',
                border: 'none',
                borderRadius: 8,
                cursor: 'pointer',
                fontWeight: 600,
                fontSize: 14,
                boxShadow: '0 4px 15px rgba(0, 229, 255, 0.3)',
                transition: 'transform 0.2s'
              }}
              onMouseEnter={(e) => e.currentTarget.style.transform = 'translateY(-2px)'}
              onMouseLeave={(e) => e.currentTarget.style.transform = 'translateY(0)'}
            >
              🔍 Discover VMs
            </button>

            <button
              onClick={logout}
              style={{
                padding: '12px 24px',
                background: 'rgba(255, 255, 255, 0.05)',
                color: '#fff',
                border: '1px solid rgba(0, 229, 255, 0.3)',
                borderRadius: 8,
                cursor: 'pointer',
                fontSize: 14
              }}
            >
              Logout
            </button>
          </div>
        </div>

        {/* Discovery Panel */}
        {showDiscovery && (
          <div style={{
            background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.1) 0%, rgba(0, 145, 234, 0.05) 100%)',
            border: '1px solid rgba(0, 229, 255, 0.2)',
            borderRadius: 12,
            padding: 20,
            marginBottom: 30,
            backdropFilter: 'blur(10px)'
          }}>
            <h3 style={{ margin: '0 0 15px 0', color: '#00e5ff', fontSize: 16 }}>Network Discovery</h3>
            <div style={{ display: 'flex', gap: 15, alignItems: 'center' }}>
              <input
                type="text"
                placeholder="Network range (e.g., 192.168.1.0/24)"
                value={networkRange}
                onChange={(e) => setNetworkRange(e.target.value)}
                style={{
                  flex: 1,
                  padding: 12,
                  background: 'rgba(0, 0, 0, 0.3)',
                  border: '1px solid rgba(0, 229, 255, 0.3)',
                  borderRadius: 8,
                  color: '#fff',
                  fontSize: 14
                }}
              />
              <button
                onClick={handleDiscoverVMs}
                disabled={discovering}
                style={{
                  padding: '12px 24px',
                  background: discovering ? '#666' : 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
                  color: discovering ? '#ccc' : '#001e3c',
                  border: 'none',
                  borderRadius: 8,
                  cursor: discovering ? 'not-allowed' : 'pointer',
                  fontWeight: 600
                }}
              >
                {discovering ? 'Scanning...' : 'Start'}
              </button>
              <button
                onClick={() => setShowDiscovery(false)}
                style={{
                  padding: '12px 24px',
                  background: 'transparent',
                  color: '#fff',
                  border: '1px solid rgba(255, 255, 255, 0.2)',
                  borderRadius: 8,
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Active Scans Live Card */}
        {recentScans.filter(s => s.status === 'running').length > 0 && (
          <div style={{
            background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.15) 0%, rgba(0, 145, 234, 0.08) 100%)',
            border: '2px solid #00e5ff',
            borderRadius: 15,
            padding: 25,
            marginBottom: 30
          }}>
            <h3 style={{ margin: '0 0 15px 0', color: '#00e5ff', fontSize: 18 }}>
              🔄 Active Scans
            </h3>

            {recentScans.filter(s => s.status === 'running').map(scan => (
              <div key={scan.id} style={{ marginBottom: 15 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                  <span style={{ color: '#fff' }}>
                    Scan #{scan.id} - {scan.target}
                  </span>
                  <span style={{ color: '#00e5ff', fontWeight: 600 }}>
                    {scan.progress || 0}%
                  </span>
                </div>

                <div style={{
                  width: '100%',
                  height: 10,
                  background: 'rgba(0, 0, 0, 0.3)',
                  borderRadius: 5,
                  overflow: 'hidden'
                }}>
                  <div style={{
                    width: `${scan.progress || 0}%`,
                    height: '100%',
                    background: 'linear-gradient(90deg, #00e5ff 0%, #0091ea 100%)',
                    transition: 'width 0.5s',
                    boxShadow: '0 0 10px rgba(0, 229, 255, 0.5)'
                  }} />
                </div>

                <p style={{ margin: '5px 0 0 0', color: '#64b5f6', fontSize: 12 }}>
                  Phase: {scan.phase || 'initializing'} | ETA: {scan.eta || 'calculating...'}
                </p>
              </div>
            ))}
          </div>
        )}

        {/* Stats Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 20, marginBottom: 30 }}>
          {[
            { label: 'Total Vulnerabilities', value: totalVulns, badge: 'Normal', color: '#00e5ff' },
            { label: 'Risk Score', value: `${riskScore}%`, badge: 'Risk Score', color: '#ff6b6b' },
            { label: 'Active Assets', value: summary.totalVMs || 0, badge: 'Active', color: '#51cf66' },
            { label: 'At Risk VMs', value: summary.atRiskVMs || 0, badge: '+5%', color: '#ffd93d' }
          ].map((stat, idx) => (
            <div key={idx} style={{
              background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.05) 0%, rgba(0, 145, 234, 0.02) 100%)',
              border: '1px solid rgba(0, 229, 255, 0.15)',
              borderRadius: 15,
              padding: 25,
              backdropFilter: 'blur(10px)',
              position: 'relative',
              overflow: 'hidden'
            }}>
              <div style={{
                position: 'absolute',
                top: 15,
                right: 15,
                padding: '4px 12px',
                background: `${stat.color}22`,
                borderRadius: 12,
                fontSize: 11,
                fontWeight: 600,
                color: stat.color
              }}>
                {stat.badge}
              </div>

              <p style={{ margin: '0 0 10px 0', fontSize: 13, color: '#90caf9' }}>{stat.label}</p>
              <h2 style={{
                margin: 0,
                fontSize: 36,
                fontWeight: 700,
                background: `linear-gradient(90deg, ${stat.color} 0%, #fff 100%)`,
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent'
              }}>
                {stat.value}
              </h2>
            </div>
          ))}
        </div>

        {/* Assets Table */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.05) 0%, rgba(0, 145, 234, 0.02) 100%)',
          border: '1px solid rgba(0, 229, 255, 0.15)',
          borderRadius: 15,
          padding: 25,
          backdropFilter: 'blur(10px)',
          marginBottom: 30
        }}>
          <h2 style={{ margin: '0 0 20px 0', color: '#00e5ff', fontSize: 20 }}>Asset Inventory</h2>

          <table style={{ width: '100%', borderCollapse: 'separate', borderSpacing: '0 8px' }}>
            <thead>
              <tr style={{ color: '#64b5f6', fontSize: 12, textTransform: 'uppercase' }}>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>Asset Name</th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>IP Address</th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>OS</th>
                <th style={{ textAlign: 'center', padding: '12px 15px' }}>Status</th>
                <th style={{ textAlign: 'center', padding: '12px 15px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {vms.length === 0 ? (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', padding: 40, color: '#64b5f6' }}>
                    No assets found. Use VM Discovery to scan your network.
                  </td>
                </tr>
              ) : (
                vms.map(vm => (
                  <tr key={vm.id} style={{
                    background: 'rgba(0, 229, 255, 0.03)',
                    border: '1px solid rgba(0, 229, 255, 0.1)'
                  }}>
                    <td style={{ padding: 15, borderRadius: '8px 0 0 8px', color: '#fff' }}>{vm.name}</td>
                    <td style={{ padding: 15, color: '#90caf9' }}>{vm.ip}</td>
                    <td style={{ padding: 15, color: '#90caf9' }}>{vm.os}</td>
                    <td style={{ padding: 15, textAlign: 'center' }}>
                      <span style={{
                        padding: '6px 14px',
                        background: 'rgba(81, 207, 102, 0.15)',
                        border: '1px solid rgba(81, 207, 102, 0.3)',
                        borderRadius: 20,
                        color: '#51cf66',
                        fontSize: 12,
                        fontWeight: 600
                      }}>
                        Active
                      </span>
                    </td>
                    <td style={{ padding: 15, borderRadius: '0 8px 8px 0', textAlign: 'center' }}>
                      <button
                        onClick={() => { setSelectedVM(vm); setShowScanModal(true); }}
                        disabled={scanning}
                        style={{
                          padding: '8px 16px',
                          background: 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
                          color: '#001e3c',
                          border: 'none',
                          borderRadius: 6,
                          cursor: scanning ? 'not-allowed' : 'pointer',
                          fontSize: 12,
                          fontWeight: 600,
                          opacity: scanning ? 0.5 : 1
                        }}
                      >
                        Scan
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Recent Scans */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.05) 0%, rgba(0, 145, 234, 0.02) 100%)',
          border: '1px solid rgba(0, 229, 255, 0.15)',
          borderRadius: 15,
          padding: 25,
          backdropFilter: 'blur(10px)'
        }}>
          <h2 style={{ margin: '0 0 20px 0', color: '#00e5ff', fontSize: 20 }}>Scan Management</h2>

          <table style={{ width: '100%', borderCollapse: 'separate', borderSpacing: '0 8px' }}>
            <thead>
              <tr style={{ color: '#64b5f6', fontSize: 12, textTransform: 'uppercase' }}>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>Scan Name</th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>Status</th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>Progress</th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>Start Time</th>
                <th style={{ textAlign: 'center', padding: '12px 15px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.length === 0 ? (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', padding: 40, color: '#64b5f6' }}>
                    No scans yet.
                  </td>
                </tr>
              ) : (
                recentScans.map(scan => (
                  <tr key={scan.id} style={{
                    background: 'rgba(0, 229, 255, 0.03)',
                    border: '1px solid rgba(0, 229, 255, 0.1)'
                  }}>
                    <td style={{ padding: 15, borderRadius: '8px 0 0 8px', color: '#fff' }}>
                      Scan #{scan.id} - {scan.target}
                    </td>
                    <td style={{ padding: 15 }}>
                      <span style={{
                        padding: '6px 14px',
                        background: scan.status === 'completed' ? 'rgba(81, 207, 102, 0.15)' :
                          scan.status === 'running' ? 'rgba(0, 229, 255, 0.15)' : 'rgba(255, 107, 107, 0.15)',
                        border: `1px solid ${scan.status === 'completed' ? 'rgba(81, 207, 102, 0.3)' :
                          scan.status === 'running' ? 'rgba(0, 229, 255, 0.3)' : 'rgba(255, 107, 107, 0.3)'}`,
                        borderRadius: 20,
                        color: scan.status === 'completed' ? '#51cf66' :
                          scan.status === 'running' ? '#00e5ff' : '#ff6b6b',
                        fontSize: 12,
                        fontWeight: 600,
                        textTransform: 'capitalize'
                      }}>
                        {scan.status}
                      </span>
                    </td>
                    <td style={{ padding: 15 }}>
                      <div style={{
                        width: 150,
                        height: 8,
                        background: 'rgba(0, 0, 0, 0.3)',
                        borderRadius: 4,
                        overflow: 'hidden'
                      }}>
                        <div style={{
                          width: `${scan.progress || 0}%`,
                          height: '100%',
                          background: 'linear-gradient(90deg, #00e5ff 0%, #0091ea 100%)',
                          transition: 'width 0.3s'
                        }} />
                      </div>
                    </td>
                    <td style={{ padding: 15, color: '#90caf9' }}>
                      {scan.startTime ? new Date(scan.startTime).toLocaleString() : 'N/A'}
                    </td>
                    <td style={{ padding: 15, borderRadius: '0 8px 8px 0', textAlign: 'center' }}>
                      <button style={{
                        padding: '6px 12px',
                        background: 'transparent',
                        color: '#00e5ff',
                        border: '1px solid #00e5ff',
                        borderRadius: 6,
                        cursor: 'pointer',
                        fontSize: 12
                      }}>
                        View
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Scan Mode Modal */}
      {showScanModal && selectedVM && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999
        }}>
          <div style={{
            background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.1) 0%, rgba(0, 145, 234, 0.05) 100%)',
            border: '1px solid rgba(0, 229, 255, 0.3)',
            borderRadius: 15,
            padding: 30,
            width: 420,
            backdropFilter: 'blur(20px)'
          }}>
            <h3 style={{ margin: '0 0 20px 0', color: '#00e5ff' }}>
              Select Scan Mode for {selectedVM.name}
            </h3>

            <div style={{ marginBottom: 20 }}>
              {[
                { mode: 'fast', time: '≈2m per host', desc: 'Quick vulnerability check' },
                { mode: 'medium', time: '≈6m per host', desc: 'Balanced scan with common ports' },
                { mode: 'full', time: '≈15m per host', desc: 'Deep scan - all ports & services' }
              ].map(item => (
                <div
                  key={item.mode}
                  onClick={() => setScanMode(item.mode)}
                  style={{
                    padding: 15,
                    margin: '10px 0',
                    background: scanMode === item.mode
                      ? 'linear-gradient(135deg, rgba(0, 229, 255, 0.2) 0%, rgba(0, 145, 234, 0.1) 100%)'
                      : 'rgba(0, 0, 0, 0.2)',
                    border: scanMode === item.mode ? '2px solid #00e5ff' : '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: 10,
                    cursor: 'pointer',
                    transition: 'all 0.3s'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
                    <strong style={{ color: '#00e5ff', textTransform: 'uppercase' }}>{item.mode}</strong>
                    <span style={{ color: '#90caf9', fontSize: 12 }}>{item.time}</span>
                  </div>
                  <p style={{ margin: 0, color: '#64b5f6', fontSize: 13 }}>{item.desc}</p>
                </div>
              ))}
            </div>

            <div style={{ display: 'flex', gap: 10 }}>
              <button
                onClick={() => handleScan(selectedVM, scanMode)}
                disabled={scanning}
                style={{
                  flex: 1,
                  padding: '12px 20px',
                  background: 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
                  color: '#001e3c',
                  border: 'none',
                  borderRadius: 8,
                  cursor: scanning ? 'not-allowed' : 'pointer',
                  fontWeight: 600
                }}
              >
                {scanning ? 'Starting...' : 'Start Scan'}
              </button>
              <button
                onClick={() => setShowScanModal(false)}
                style={{
                  padding: '12px 20px',
                  background: 'transparent',
                  color: '#fff',
                  border: '1px solid rgba(255, 255, 255, 0.3)',
                  borderRadius: 8,
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
