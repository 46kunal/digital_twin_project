import React, { useEffect, useState } from 'react';
import Sidebar from './Sidebar';
import api from '../services/api';

export default function Reports() {
  const [scans, setScans] = useState([]);
  const [generating, setGenerating] = useState(null);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = () => {
    api.get('/api/scans?per_page=100')
      .then(res => {
        const items = res.data.items || [];
        setScans(items.filter(s => s.status === 'completed'));
      })
      .catch(err => console.error(err));
  };

  const generateReport = async (scanId, format = 'pdf') => {
    setGenerating(scanId);
    try {
      const response = await api.get(`/api/scan/${scanId}/report/${format}`, {
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `scan_${scanId}_report.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err);
      alert('Report generation failed. Make sure reporting module is configured.');
    } finally {
      setGenerating(null);
    }
  };

  const generateBulkReport = async () => {
    setGenerating('bulk');
    try {
      // Generate a combined report for all completed scans
      const response = await api.post('/api/reports/bulk', {
        scan_ids: scans.map(s => s.id)
      }, {
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `bulk_report_${new Date().toISOString().split('T')[0]}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err);
      alert('Bulk report generation not yet implemented');
    } finally {
      setGenerating(null);
    }
  };

  const filteredScans = scans.filter(scan => {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const scanDate = new Date(scan.start_time);
    
    if (filter === 'recent') return scanDate > thirtyDaysAgo;
    if (filter === 'older') return scanDate <= thirtyDaysAgo;
    return true;
  });

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#0a1929' }}>
      <Sidebar />
      
      <div style={{ marginLeft: 240, flex: 1, padding: 40 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 30 }}>
          <h1 style={{
            margin: 0,
            fontSize: 32,
            fontWeight: 700,
            background: 'linear-gradient(90deg, #00e5ff 0%, #fff 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>
            Reports Hub
          </h1>

          <button
            onClick={generateBulkReport}
            disabled={generating === 'bulk' || scans.length === 0}
            style={{
              padding: '12px 24px',
              background: generating === 'bulk' || scans.length === 0
                ? '#666'
                : 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
              color: generating === 'bulk' || scans.length === 0 ? '#ccc' : '#001e3c',
              border: 'none',
              borderRadius: 8,
              cursor: generating === 'bulk' || scans.length === 0 ? 'not-allowed' : 'pointer',
              fontWeight: 600,
              fontSize: 14
            }}
          >
            {generating === 'bulk' ? '⏳ Generating...' : '📊 Generate Bulk Report'}
          </button>
        </div>

        {/* Filter Buttons */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 30 }}>
          {['all', 'recent', 'older'].map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                padding: '8px 16px',
                background: filter === f 
                  ? 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)'
                  : 'rgba(0, 0, 0, 0.3)',
                color: filter === f ? '#001e3c' : '#fff',
                border: filter === f ? 'none' : '1px solid rgba(0, 229, 255, 0.3)',
                borderRadius: 8,
                cursor: 'pointer',
                fontWeight: 600,
                fontSize: 12,
                textTransform: 'capitalize'
              }}
            >
              {f === 'recent' ? 'Last 30 Days' : f === 'older' ? 'Older' : 'All Reports'} ({
                f === 'all' ? scans.length :
                f === 'recent' ? scans.filter(s => {
                  const d = new Date(s.start_time);
                  const t = new Date();
                  t.setDate(t.getDate() - 30);
                  return d > t;
                }).length :
                scans.filter(s => {
                  const d = new Date(s.start_time);
                  const t = new Date();
                  t.setDate(t.getDate() - 30);
                  return d <= t;
                }).length
              })
            </button>
          ))}
        </div>

        {/* Reports Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: 20 }}>
          {filteredScans.length === 0 ? (
            <div style={{
              gridColumn: '1 / -1',
              textAlign: 'center',
              padding: 60,
              background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.05) 0%, rgba(0, 145, 234, 0.02) 100%)',
              border: '1px solid rgba(0, 229, 255, 0.15)',
              borderRadius: 15,
              color: '#64b5f6'
            }}>
              <h2 style={{ color: '#00e5ff' }}>No completed scans</h2>
              <p>Run a scan to generate reports</p>
            </div>
          ) : (
            filteredScans.map(scan => (
              <div key={scan.id} style={{
                background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.05) 0%, rgba(0, 145, 234, 0.02) 100%)',
                border: '1px solid rgba(0, 229, 255, 0.15)',
                borderRadius: 15,
                padding: 25,
                backdropFilter: 'blur(10px)',
                transition: 'transform 0.2s',
                cursor: 'pointer'
              }}
              onMouseEnter={(e) => e.currentTarget.style.transform = 'translateY(-5px)'}
              onMouseLeave={(e) => e.currentTarget.style.transform = 'translateY(0)'}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 15 }}>
                  <h3 style={{ margin: 0, color: '#00e5ff', fontSize: 18 }}>
                    📄 Scan Report #{scan.id}
                  </h3>
                  <span style={{
                    padding: '4px 10px',
                    background: 'rgba(81, 207, 102, 0.15)',
                    border: '1px solid rgba(81, 207, 102, 0.3)',
                    borderRadius: 12,
                    color: '#51cf66',
                    fontSize: 11,
                    fontWeight: 600
                  }}>
                    Completed
                  </span>
                </div>

                <div style={{ marginBottom: 15 }}>
                  <p style={{ margin: '5px 0', color: '#90caf9', fontSize: 13 }}>
                    <strong>Target:</strong> {scan.target}
                  </p>
                  <p style={{ margin: '5px 0', color: '#90caf9', fontSize: 13 }}>
                    <strong>Date:</strong> {scan.start_time ? new Date(scan.start_time).toLocaleDateString() : 'N/A'}
                  </p>
                  <p style={{ margin: '5px 0', color: '#90caf9', fontSize: 13 }}>
                    <strong>Time:</strong> {scan.start_time ? new Date(scan.start_time).toLocaleTimeString() : 'N/A'}
                  </p>
                </div>

                <div style={{ display: 'flex', gap: 10 }}>
                  <button
                    onClick={() => generateReport(scan.id, 'pdf')}
                    disabled={generating === scan.id}
                    style={{
                      flex: 1,
                      padding: '10px',
                      background: generating === scan.id
                        ? '#666'
                        : 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
                      color: generating === scan.id ? '#ccc' : '#001e3c',
                      border: 'none',
                      borderRadius: 8,
                      cursor: generating === scan.id ? 'not-allowed' : 'pointer',
                      fontSize: 13,
                      fontWeight: 600
                    }}
                  >
                    {generating === scan.id ? '⏳ Generating...' : '📥 Download PDF'}
                  </button>
                  <button
                    onClick={() => window.location.href = `/scans#${scan.id}`}
                    style={{
                      padding: '10px 15px',
                      background: 'transparent',
                      color: '#00e5ff',
                      border: '1px solid #00e5ff',
                      borderRadius: 8,
                      cursor: 'pointer',
                      fontSize: 13
                    }}
                  >
                    👁️ View
                  </button>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Report Templates Section */}
        <div style={{
          marginTop: 40,
          background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.05) 0%, rgba(0, 145, 234, 0.02) 100%)',
          border: '1px solid rgba(0, 229, 255, 0.15)',
          borderRadius: 15,
          padding: 25,
          backdropFilter: 'blur(10px)'
        }}>
          <h2 style={{ margin: '0 0 20px 0', color: '#00e5ff', fontSize: 20 }}>
            Report Templates
          </h2>
          
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 15 }}>
            {[
              { name: 'Executive Summary', desc: 'High-level overview for management', icon: '📊' },
              { name: 'Technical Details', desc: 'Detailed vulnerability analysis', icon: '🔬' },
              { name: 'Compliance Report', desc: 'Regulatory compliance status', icon: '✅' }
            ].map((template, idx) => (
              <div key={idx} style={{
                background: 'rgba(0, 0, 0, 0.2)',
                padding: 15,
                borderRadius: 10,
                border: '1px solid rgba(0, 229, 255, 0.1)',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: 32, marginBottom: 10 }}>{template.icon}</div>
                <h4 style={{ margin: '0 0 5px 0', color: '#00e5ff', fontSize: 14 }}>{template.name}</h4>
                <p style={{ margin: 0, color: '#64b5f6', fontSize: 12 }}>{template.desc}</p>
                <button style={{
                  marginTop: 10,
                  padding: '6px 12px',
                  background: 'transparent',
                  color: '#00e5ff',
                  border: '1px solid #00e5ff',
                  borderRadius: 6,
                  cursor: 'pointer',
                  fontSize: 11,
                  opacity: 0.5
                }}>
                  Coming Soon
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
