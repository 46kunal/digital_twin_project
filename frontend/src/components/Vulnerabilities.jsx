import React, { useEffect, useState } from 'react';
import Sidebar from './Sidebar';
import api from '../services/api';

export default function Vulnerabilities() {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [stats, setStats] = useState({ critical: 0, high: 0, medium: 0, low: 0 });

  useEffect(() => {
    loadVulnerabilities();
    loadStats();
  }, []);

  const loadVulnerabilities = () => {
    // Get all scans and their vulnerabilities
    api.get('/api/scans?per_page=100')
      .then(res => {
        const scans = res.data.items || [];
        const promises = scans.map(scan =>
          api.get(`/api/scan/${scan.id}/vulnerabilities`)
            .then(vulnRes =>
              vulnRes.data.map(v => ({
                ...v,
                scan_id: scan.id,
                target: scan.target,
              }))
            )
            .catch(() => [])
        );
        return Promise.all(promises);
      })
      .then(results => {
        const allVulns = results.flat();
        setVulnerabilities(allVulns);
      })
      .catch(err => console.error(err));
  };

  const loadStats = () => {
    api.get('/api/vulnerabilities/by-severity')
      .then(res => setStats(res.data || { critical: 0, high: 0, medium: 0, low: 0 }))
      .catch(err => console.error(err));
  };

  const getSeverityColor = (severity) => {
    const sev = (severity || '').toLowerCase();
    if (sev.includes('crit')) return { bg: 'rgba(255, 71, 71, 0.15)', border: 'rgba(255, 71, 71, 0.3)', text: '#ff4747' };
    if (sev.includes('high')) return { bg: 'rgba(255, 152, 0, 0.15)', border: 'rgba(255, 152, 0, 0.3)', text: '#ff9800' };
    if (sev.includes('medium')) return { bg: 'rgba(255, 211, 61, 0.15)', border: 'rgba(255, 211, 61, 0.3)', text: '#ffd93d' };
    return { bg: 'rgba(81, 207, 102, 0.15)', border: 'rgba(81, 207, 102, 0.3)', text: '#51cf66' };
  };

  // Use issue_id, description, service, target for search
  const filteredVulns = vulnerabilities.filter(v => {
    const needle = search.toLowerCase();
    const matchesSearch =
      (v.issue_id || '').toLowerCase().includes(needle) ||
      (v.description || '').toLowerCase().includes(needle) ||
      (v.service || '').toLowerCase().includes(needle) ||
      (v.target || '').toLowerCase().includes(needle);
    const matchesFilter =
      filter === 'all' || (v.severity || '').toLowerCase().includes(filter.toLowerCase());
    return matchesSearch && matchesFilter;
  });

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#0a1929' }}>
      <Sidebar />

      <div style={{ marginLeft: 240, flex: 1, padding: 40 }}>
        <h1
          style={{
            margin: '0 0 30px 0',
            fontSize: 32,
            fontWeight: 700,
            background: 'linear-gradient(90deg, #00e5ff 0%, #fff 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
          }}
        >
          Vulnerability Index
        </h1>

        {/* Stats Cards */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: 20,
            marginBottom: 30,
          }}
        >
          {[
            { label: 'Critical', value: stats.critical, color: '#ff4747' },
            { label: 'High', value: stats.high, color: '#ff9800' },
            { label: 'Medium', value: stats.medium, color: '#ffd93d' },
            { label: 'Low', value: stats.low, color: '#51cf66' },
          ].map((stat, idx) => (
            <div
              key={idx}
              style={{
                background:
                  'linear-gradient(135deg, rgba(0, 229, 255, 0.05) 0%, rgba(0, 145, 234, 0.02) 100%)',
                border: '1px solid rgba(0, 229, 255, 0.15)',
                borderRadius: 15,
                padding: 25,
                backdropFilter: 'blur(10px)',
              }}
            >
              <p
                style={{
                  margin: '0 0 10px 0',
                  fontSize: 13,
                  color: '#90caf9',
                }}
              >
                {stat.label}
              </p>
              <h2
                style={{
                  margin: 0,
                  fontSize: 36,
                  fontWeight: 700,
                  color: stat.color,
                }}
              >
                {stat.value}
              </h2>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div style={{ display: 'flex', gap: 15, marginBottom: 30 }}>
          <input
            type="text"
            placeholder="🔍 Search vulnerabilities..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              flex: 1,
              padding: 12,
              background: 'rgba(0, 0, 0, 0.3)',
              border: '1px solid rgba(0, 229, 255, 0.3)',
              borderRadius: 8,
              color: '#fff',
              fontSize: 14,
            }}
          />

          <div style={{ display: 'flex', gap: 10 }}>
            {['all', 'critical', 'high', 'medium', 'low'].map((f) => (
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
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* Vulnerabilities Table */}
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
                  Issue ID
                </th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>
                  Severity
                </th>
                <th style={{ textAlign: 'center', padding: '12px 15px' }}>
                  Risk Score
                </th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>
                  Likelihood
                </th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>
                  Impact
                </th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>
                  Service
                </th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>
                  Port
                </th>
                <th style={{ textAlign: 'left', padding: '12px 15px' }}>
                  Target
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredVulns.length === 0 ? (
                <tr>
                  <td
                    colSpan="8"
                    style={{
                      textAlign: 'center',
                      padding: 40,
                      color: '#64b5f6',
                    }}
                  >
                    No vulnerabilities found
                  </td>
                </tr>
              ) : (
                filteredVulns.map((vuln, idx) => {
                  const sevColors = getSeverityColor(vuln.severity);
                  return (
                    <tr
                      key={idx}
                      style={{
                        background: 'rgba(0, 229, 255, 0.03)',
                        border: '1px solid rgba(0, 229, 255, 0.1)',
                        cursor: 'pointer',
                      }}
                    >
                      <td
                        style={{
                          padding: 15,
                          borderRadius: '8px 0 0 8px',
                          color: '#00e5ff',
                          fontWeight: 600,
                        }}
                      >
                        {vuln.issue_id || 'N/A'}
                      </td>
                      <td style={{ padding: 15 }}>
                        <span
                          style={{
                            padding: '6px 14px',
                            background: sevColors.bg,
                            border: `1px solid ${sevColors.border}`,
                            borderRadius: 20,
                            color: sevColors.text,
                            fontSize: 12,
                            fontWeight: 600,
                            textTransform: 'capitalize',
                          }}
                        >
                          {vuln.severity || 'Unknown'}
                        </span>
                      </td>
                      <td
                        style={{
                          padding: 15,
                          textAlign: 'center',
                          color: sevColors.text,
                          fontWeight: 700,
                        }}
                      >
                        {vuln.risk_score != null ? vuln.risk_score : 'N/A'}
                      </td>
                      <td style={{ padding: 15, color: '#90caf9' }}>
                        {vuln.likelihood || 'Unknown'}
                      </td>
                      <td style={{ padding: 15, color: '#90caf9' }}>
                        {vuln.impact || 'Unknown'}
                      </td>
                      <td style={{ padding: 15, color: '#90caf9' }}>
                        {vuln.service || 'Unknown'}
                      </td>
                      <td style={{ padding: 15, color: '#90caf9' }}>
                        {vuln.port || 'N/A'}
                      </td>
                      <td
                        style={{
                          padding: 15,
                          borderRadius: '0 8px 8px 0',
                          color: '#90caf9',
                        }}
                      >
                        {vuln.target || `Scan #${vuln.scan_id}`}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
