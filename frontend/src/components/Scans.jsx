import React, { useEffect, useState } from 'react';
import Sidebar from './Sidebar';
import api from '../services/api';
import { initSocket } from '../services/socket';

export default function Scans() {
  const [scans, setScans] = useState([]);
  const [filter, setFilter] = useState('all');
  const [selectedScan, setSelectedScan] = useState(null);
  const [showDetails, setShowDetails] = useState(false);

  useEffect(() => {
    loadScans();

    const socket = initSocket();
    socket.on('scan_update', (data) => {
      setScans((prevScans) =>
        prevScans.map((scan) =>
          scan.id === data.scan_id
            ? {
                ...scan,
                status: data.status,
                progress: data.progress,
                phase: data.phase,
              }
            : scan
        )
      );
      if (data.status === 'completed' || data.status === 'failed') {
        setTimeout(loadScans, 1000);
      }
    });

    return () => {
      socket.off('scan_update');
      socket.disconnect?.();
    };
  }, []);

  const loadScans = () => {
    api
      .get('/api/scans?per_page=100')
      .then((res) => {
        const items = res.data.items || [];
        setScans(
          items.map((s) => ({
            id: s.id,
            target: s.target,
            status: s.status,
            progress: s.progress || 0,
            phase: s.phase,
            eta: s.eta,
            start_time: s.starttime || s.start_time,
            end_time: s.endtime || s.end_time,
            vulnerability_count: s.vulnerabilityCount ?? s.vulnerability_count,
          }))
        );
      })
      .catch((err) => console.error(err));
  };

const viewScanDetails = async (scanId) => {
  try {
    // 1) Get main scan details
    const { data: scan } = await api.get(`/api/scan/${scanId}`);

    // 2) Get vulnerabilities for this scan
    const { data: vulns } = await api.get(
      `/api/scan/${scanId}/vulnerabilities`
    );

    // 3) Combine into one object the modal uses
    setSelectedScan({
      scan_id: scan.scanid ?? scan.scan_id ?? scan.id,
      target: scan.target,
      status: scan.status,
      progress: scan.progress || 0,
      phase: scan.phase,
      start_time: scan.starttime || scan.start_time,
      end_time: scan.endtime || scan.end_time,
      vulnerability_count: vulns.length,
      vulnerabilities: vulns,
    });

    setShowDetails(true);
  } catch (err) {
    console.error(err);
    alert('Failed to load scan details');
  }
};

  const downloadReport = async (scanId) => {
    try {
      const response = await api.get(`/api/scan/${scanId}/report/pdf`, {
        responseType: 'blob',
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `scan_${scanId}_report.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      console.error(err);
      alert('Report generation not available or failed');
    }
  };

  const filteredScans = scans.filter((scan) => {
    if (filter === 'all') return true;
    return scan.status === filter;
  });

  const getSeverityColor = (severity) => {
    const sev = (severity || '').toLowerCase();
    if (sev.includes('crit'))
      return {
        bg: 'rgba(255, 71, 71, 0.15)',
        border: 'rgba(255, 71, 71, 0.3)',
        text: '#ff4747',
      };
    if (sev.includes('high'))
      return {
        bg: 'rgba(255, 152, 0, 0.15)',
        border: 'rgba(255, 152, 0, 0.3)',
        text: '#ff9800',
      };
    if (sev.includes('medium'))
      return {
        bg: 'rgba(255, 211, 61, 0.15)',
        border: 'rgba(255, 211, 61, 0.3)',
        text: '#ffd93d',
      };
    return {
      bg: 'rgba(81, 207, 102, 0.15)',
      border: 'rgba(81, 207, 102, 0.3)',
      text: '#51cf66',
    };
  };

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#0a1929' }}>
      <Sidebar />

      <div style={{ marginLeft: 240, flex: 1, padding: 40 }}>
        {/* Header + filters */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 30,
          }}
        >
          <h1
            style={{
              margin: 0,
              fontSize: 32,
              fontWeight: 700,
              background: 'linear-gradient(90deg, #00e5ff 0%, #fff 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}
          >
            Scan Management
          </h1>

          <div style={{ display: 'flex', gap: 10 }}>
            {['all', 'running', 'completed', 'failed'].map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                style={{
                  padding: '8px 16px',
                  background:
                    filter === f
                      ? 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)'
                      : 'rgba(0, 0, 0, 0.3)',
                  color: filter === f ? '#001e3c' : '#fff',
                  border:
                    filter === f
                      ? 'none'
                      : '1px solid rgba(0, 229, 255, 0.3)',
                  borderRadius: 8,
                  cursor: 'pointer',
                  fontWeight: 600,
                  fontSize: 12,
                  textTransform: 'capitalize',
                }}
              >
                {f} (
                {scans.filter((s) => f === 'all' || s.status === f).length})
              </button>
            ))}
          </div>
        </div>

        {/* Active Scans */}
        {filteredScans.filter((s) => s.status === 'running').length > 0 && (
          <div
            style={{
              background:
                'linear-gradient(135deg, rgba(0, 229, 255, 0.15) 0%, rgba(0, 145, 234, 0.08) 100%)',
              border: '2px solid #00e5ff',
              borderRadius: 15,
              padding: 25,
              marginBottom: 30,
            }}
          >
            <h3
              style={{
                margin: '0 0 20px 0',
                color: '#00e5ff',
                fontSize: 18,
              }}
            >
              🔄 Active Scans (
              {filteredScans.filter((s) => s.status === 'running').length})
            </h3>

            {filteredScans
              .filter((s) => s.status === 'running')
              .map((scan) => (
                <div
                  key={scan.id}
                  style={{
                    background: 'rgba(0, 0, 0, 0.2)',
                    padding: 15,
                    borderRadius: 10,
                    marginBottom: 15,
                    border: '1px solid rgba(0, 229, 255, 0.2)',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      marginBottom: 10,
                    }}
                  >
                    <div>
                      <h4
                        style={{ margin: '0 0 5px 0', color: '#fff' }}
                      >{`Scan #${scan.id} - ${scan.target}`}</h4>
                      <p
                        style={{
                          margin: 0,
                          color: '#64b5f6',
                          fontSize: 12,
                        }}
                      >
                        Phase: <strong>{scan.phase || 'initializing'}</strong> |{' '}
                        ETA: {scan.eta || 'calculating...'}
                      </p>
                    </div>
                    <span
                      style={{
                        color: '#00e5ff',
                        fontWeight: 700,
                        fontSize: 20,
                      }}
                    >
                      {scan.progress}%
                    </span>
                  </div>

                  <div
                    style={{
                      width: '100%',
                      height: 12,
                      background: 'rgba(0, 0, 0, 0.3)',
                      borderRadius: 6,
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        width: `${scan.progress}%`,
                        height: '100%',
                        background:
                          'linear-gradient(90deg, #00e5ff 0%, #0091ea 100%)',
                        transition: 'width 0.5s',
                        boxShadow: '0 0 15px rgba(0, 229, 255, 0.7)',
                      }}
                    />
                  </div>
                </div>
              ))}
          </div>
        )}

        {/* All Scans Table */}
        <div
          style={{
            background:
              'linear-gradient(135deg, rgba(0, 229, 255, 0.05) 0%, rgba(0, 145, 234, 0.02) 100%)',
            border: '1px solid rgba(0, 229, 255, 0.15)',
            borderRadius: 15,
            padding: 25,
            backdropFilter: 'blur(10px)',
          }}
        >
          <h2
            style={{
              margin: '0 0 20px 0',
              color: '#00e5ff',
              fontSize: 20,
            }}
          >
            Scan History
          </h2>

          <table
            style={{
              width: '100%',
              borderCollapse: 'separate',
              borderSpacing: '0 8px',
            }}
          >
            <thead>
              <tr
                style={{
                  color: '#64b5f6',
                  fontSize: 12,
                  textTransform: 'uppercase',
                }}
              >
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>
                  ID
                </th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>
                  Target
                </th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>
                  Status
                </th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>
                  Progress
                </th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>
                  Start Time
                </th>
                <th
                  style={{
                    textAlign: 'center',
                    padding: '12px 15px',
                  }}
                >
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredScans.length === 0 ? (
                <tr>
                  <td
                    colSpan="6"
                    style={{
                      textAlign: 'center',
                      padding: 40,
                      color: '#64b5f6',
                    }}
                  >
                    No scans found
                  </td>
                </tr>
              ) : (
                filteredScans.map((scan) => (
                  <tr
                    key={scan.id}
                    style={{
                      background: 'rgba(0, 229, 255, 0.03)',
                      border: '1px solid rgba(0, 229, 255, 0.1)',
                    }}
                  >
                    <td
                      style={{
                        padding: 15,
                        borderRadius: '8px 0 0 8px',
                        color: '#fff',
                      }}
                    >
                      #{scan.id}
                    </td>
                    <td style={{ padding: 15, color: '#90caf9' }}>
                      {scan.target}
                    </td>
                    <td style={{ padding: 15 }}>
                      <span
                        style={{
                          padding: '6px 14px',
                          background:
                            scan.status === 'completed'
                              ? 'rgba(81, 207, 102, 0.15)'
                              : scan.status === 'running'
                              ? 'rgba(0, 229, 255, 0.15)'
                              : scan.status === 'queued'
                              ? 'rgba(255, 211, 61, 0.15)'
                              : 'rgba(255, 107, 107, 0.15)',
                          border: `1px solid ${
                            scan.status === 'completed'
                              ? 'rgba(81, 207, 102, 0.3)'
                              : scan.status === 'running'
                              ? 'rgba(0, 229, 255, 0.3)'
                              : scan.status === 'queued'
                              ? 'rgba(255, 211, 61, 0.3)'
                              : 'rgba(255, 107, 107, 0.3)'
                          }`,
                          borderRadius: 20,
                          color:
                            scan.status === 'completed'
                              ? '#51cf66'
                              : scan.status === 'running'
                              ? '#00e5ff'
                              : scan.status === 'queued'
                              ? '#ffd93d'
                              : '#ff6b6b',
                          fontSize: 12,
                          fontWeight: 600,
                          textTransform: 'capitalize',
                        }}
                      >
                        {scan.status}
                      </span>
                    </td>
                    <td style={{ padding: 15 }}>
                      <div
                        style={{
                          width: 100,
                          height: 8,
                          background: 'rgba(0, 0, 0, 0.3)',
                          borderRadius: 4,
                          overflow: 'hidden',
                          display: 'inline-block',
                        }}
                      >
                        <div
                          style={{
                            width: `${scan.progress}%`,
                            height: '100%',
                            background:
                              'linear-gradient(90deg, #00e5ff 0%, #0091ea 100%)',
                            transition: 'width 0.3s',
                          }}
                        />
                      </div>
                      <span
                        style={{
                          marginLeft: 10,
                          color: '#90caf9',
                          fontSize: 12,
                        }}
                      >
                        {scan.progress}%
                      </span>
                    </td>
                    <td style={{ padding: 15, color: '#90caf9' }}>
                      {scan.start_time
                        ? new Date(scan.start_time).toLocaleString()
                        : 'N/A'}
                    </td>
                    <td
                      style={{
                        padding: 15,
                        borderRadius: '0 8px 8px 0',
                        textAlign: 'center',
                      }}
                    >
                      <button
                        onClick={() => viewScanDetails(scan.id)}
                        style={{
                          padding: '6px 12px',
                          background: 'transparent',
                          color: '#00e5ff',
                          border: '1px solid #00e5ff',
                          borderRadius: 6,
                          cursor: 'pointer',
                          fontSize: 12,
                          marginRight: 5,
                        }}
                      >
                        View
                      </button>
                      {scan.status === 'completed' && (
                        <button
                          onClick={() => downloadReport(scan.id)}
                          style={{
                            padding: '6px 12px',
                            background:
                              'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
                            color: '#001e3c',
                            border: 'none',
                            borderRadius: 6,
                            cursor: 'pointer',
                            fontSize: 12,
                            fontWeight: 600,
                          }}
                        >
                          📄 Report
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Scan Details Modal */}
      {showDetails && selectedScan && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            overflow: 'auto',
            padding: 20,
          }}
        >
          <div
            style={{
              background:
                'linear-gradient(135deg, rgba(0, 229, 255, 0.1) 0%, rgba(0, 145, 234, 0.05) 100%)',
              border: '1px solid rgba(0, 229, 255, 0.3)',
              borderRadius: 15,
              padding: 30,
              width: '90%',
              maxWidth: 1000,
              maxHeight: '90vh',
              overflow: 'auto',
              backdropFilter: 'blur(20px)',
            }}
          >
            {/* Header */}
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                marginBottom: 20,
              }}
            >
              <h3 style={{ margin: 0, color: '#00e5ff' }}>
                Scan #{selectedScan.scan_id} Details
              </h3>
              <button
                onClick={() => setShowDetails(false)}
                style={{
                  background: 'transparent',
                  color: '#fff',
                  border: 'none',
                  fontSize: 24,
                  cursor: 'pointer',
                }}
              >
                ×
              </button>
            </div>

            {/* Meta info */}
            <div style={{ marginBottom: 20 }}>
              <p style={{ color: '#90caf9', margin: '10px 0' }}>
                <strong>Target:</strong> {selectedScan.target}
              </p>
              <p style={{ color: '#90caf9', margin: '10px 0' }}>
                <strong>Status:</strong>{' '}
                <span
                  style={{
                    padding: '4px 10px',
                    background:
                      selectedScan.status === 'completed'
                        ? 'rgba(81, 207, 102, 0.15)'
                        : 'rgba(0, 229, 255, 0.15)',
                    borderRadius: 12,
                    color:
                      selectedScan.status === 'completed'
                        ? '#51cf66'
                        : '#00e5ff',
                    fontWeight: 600,
                  }}
                >
                  {selectedScan.status}
                </span>
              </p>
              <p style={{ color: '#90caf9', margin: '10px 0' }}>
                <strong>Progress:</strong> {selectedScan.progress}%
              </p>
              <p style={{ color: '#90caf9', margin: '10px 0' }}>
                <strong>Phase:</strong> {selectedScan.phase}
              </p>
              <p style={{ color: '#90caf9', margin: '10px 0' }}>
                <strong>Start Time:</strong>{' '}
                {selectedScan.start_time
                  ? new Date(selectedScan.start_time).toLocaleString()
                  : 'N/A'}
              </p>
              <p style={{ color: '#90caf9', margin: '10px 0' }}>
                <strong>End Time:</strong>{' '}
                {selectedScan.end_time
                  ? new Date(selectedScan.end_time).toLocaleString()
                  : 'In progress'}
              </p>
              <p style={{ color: '#90caf9', margin: '10px 0' }}>
                <strong>Vulnerabilities:</strong>{' '}
                {selectedScan.vulnerability_count ?? 0}
              </p>
            </div>

            {/* Vulnerabilities table */}
            <div
              style={{
                background: 'rgba(0, 0, 0, 0.3)',
                padding: 15,
                borderRadius: 8,
                marginBottom: 20,
                maxHeight: 300,
                overflow: 'auto',
              }}
            >
              <h4
                style={{
                  margin: '0 0 10px 0',
                  color: '#00e5ff',
                }}
              >
                Detected Vulnerabilities
              </h4>
              {selectedScan.vulnerabilities &&
              selectedScan.vulnerabilities.length > 0 ? (
                <table
                  style={{
                    width: '100%',
                    borderCollapse: 'separate',
                    borderSpacing: '0 6px',
                    fontSize: 12,
                  }}
                >
                  <thead>
                    <tr
                      style={{
                        color: '#64b5f6',
                        textTransform: 'uppercase',
                      }}
                    >
                      <th style={{ textAlign: 'left', padding: '6px 8px' }}>
                        Issue ID
                      </th>
                      <th style={{ textAlign: 'left', padding: '6px 8px' }}>
                        CVE
                      </th>
                      <th style={{ textAlign: 'left', padding: '6px 8px' }}>
                        Severity
                      </th>
                      <th style={{ textAlign: 'left', padding: '6px 8px' }}>
                        CVSS
                      </th>
                      <th style={{ textAlign: 'left', padding: '6px 8px' }}>
                        Risk Score
                      </th>
                      <th style={{ textAlign: 'left', padding: '6px 8px' }}>
                        Port / Service
                      </th>
                      <th style={{ textAlign: 'left', padding: '6px 8px' }}>
                        Description
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedScan.vulnerabilities.map((v) => {
                      const colors = getSeverityColor(v.severity);
                      return (
                        <tr key={v.id}>
                          <td
                            style={{
                              padding: '6px 8px',
                              color: '#fff',
                            }}
                          >
                            {v.id}
                          </td>
                          <td
                            style={{
                              padding: '6px 8px',
                              color: '#90caf9',
                            }}
                          >
                            {v.cveid || v.cve || 'N/A'}
                          </td>
                          <td
                            style={{
                              padding: '6px 8px',
                            }}
                          >
                            <span
                              style={{
                                padding: '4px 10px',
                                borderRadius: 12,
                                background: colors.bg,
                                border: `1px solid ${colors.border}`,
                                color: colors.text,
                                fontWeight: 600,
                              }}
                            >
                              {v.severity || 'Unknown'}
                            </span>
                          </td>
                          <td
                            style={{
                              padding: '6px 8px',
                              color: '#90caf9',
                            }}
                          >
                            {v.cvssscore != null ? v.cvssscore : 'N/A'}
                          </td>
                          <td
                            style={{
                              padding: '6px 8px',
                              color: '#90caf9',
                            }}
                          >
                            {v.riskscore != null ? v.riskscore : 'N/A'}
                          </td>
                          <td
                            style={{
                              padding: '6px 8px',
                              color: '#90caf9',
                            }}
                          >
                            {v.port
                              ? `${v.port} / ${v.service || ''}`.trim()
                              : v.service || 'N/A'}
                          </td>
                          <td
                            style={{
                              padding: '6px 8px',
                              color: '#cfd8dc',
                            }}
                          >
                            {v.description || 'No description'}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <p style={{ color: '#90caf9', margin: 0 }}>
                  No vulnerabilities recorded for this scan.
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
