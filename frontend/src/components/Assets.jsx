import React, { useEffect, useState } from 'react';
import Sidebar from './Sidebar';
import api from '../services/api';

export default function Assets() {
  const [vms, setVms] = useState([]);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');

  useEffect(() => {
    loadAssets();
  }, []);

  const loadAssets = () => {
    api.get('/api/vms')
      .then(res => {
        const serverData = res.data;
        const arr = Array.isArray(serverData?.vms) ? serverData.vms : (Array.isArray(serverData) ? serverData : []);
        const mapped = arr.map(vm => ({
          id: vm.id,
          name: vm.name || vm.hostname || `vm-${vm.id}`,
          ip: vm.ip || vm.ip_address || '',
          os: vm.os || 'Unknown',
          status: 'Active'
        }));
        setVms(mapped);
      })
      .catch(err => console.error(err));
  };

  const startScan = async (vm) => {
    try {
      await api.post('/api/scanstart', {
        target: vm.ip,
        mode: 'fast',
        parse_xml: true
      });
      alert(`Scan started for ${vm.ip}`);
    } catch (err) {
      console.error(err);
      alert('Failed to start scan');
    }
  };

  const viewDetails = (vm) => {
    window.location.href = `/vulnerabilities?vm=${vm.id}`;
  };

  const filteredVMs = vms.filter(vm => {
    const matchesSearch = vm.name.toLowerCase().includes(search.toLowerCase()) || 
                         vm.ip.toLowerCase().includes(search.toLowerCase());
    const matchesFilter = filter === 'all' || vm.status.toLowerCase() === filter.toLowerCase();
    return matchesSearch && matchesFilter;
  });

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#0a1929' }}>
      <Sidebar />
      
      <div style={{ marginLeft: 240, flex: 1, padding: 40 }}>
        <h1 style={{
          margin: '0 0 30px 0',
          fontSize: 32,
          fontWeight: 700,
          background: 'linear-gradient(90deg, #00e5ff 0%, #fff 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent'
        }}>
          Asset Inventory
        </h1>

        {/* Filters */}
        <div style={{ display: 'flex', gap: 15, marginBottom: 30 }}>
          <input
            type="text"
            placeholder="🔍 Search assets..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
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
          
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{
              padding: 12,
              background: 'rgba(0, 0, 0, 0.3)',
              border: '1px solid rgba(0, 229, 255, 0.3)',
              borderRadius: 8,
              color: '#fff',
              fontSize: 14,
              cursor: 'pointer'
            }}
          >
            <option value="all">All Assets</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </select>
        </div>

        {/* Assets Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 20 }}>
          {filteredVMs.map(vm => (
            <div key={vm.id} style={{
              background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.05) 0%, rgba(0, 145, 234, 0.02) 100%)',
              border: '1px solid rgba(0, 229, 255, 0.15)',
              borderRadius: 15,
              padding: 20,
              backdropFilter: 'blur(10px)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 15 }}>
                <h3 style={{ margin: 0, color: '#00e5ff', fontSize: 18 }}>{vm.name}</h3>
                <span style={{
                  padding: '4px 10px',
                  background: 'rgba(81, 207, 102, 0.15)',
                  border: '1px solid rgba(81, 207, 102, 0.3)',
                  borderRadius: 12,
                  color: '#51cf66',
                  fontSize: 11,
                  fontWeight: 600
                }}>
                  {vm.status}
                </span>
              </div>
              
              <div style={{ marginBottom: 10 }}>
                <p style={{ margin: '5px 0', color: '#90caf9', fontSize: 13 }}>
                  <strong>IP:</strong> {vm.ip}
                </p>
                <p style={{ margin: '5px 0', color: '#90caf9', fontSize: 13 }}>
                  <strong>OS:</strong> {vm.os}
                </p>
              </div>
              
              <div style={{ display: 'flex', gap: 10, marginTop: 15 }}>
                <button 
                  onClick={() => startScan(vm)}
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    background: 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
                    color: '#001e3c',
                    border: 'none',
                    borderRadius: 6,
                    cursor: 'pointer',
                    fontSize: 12,
                    fontWeight: 600
                  }}
                >
                  Scan
                </button>
                <button 
                  onClick={() => viewDetails(vm)}
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    background: 'transparent',
                    color: '#00e5ff',
                    border: '1px solid #00e5ff',
                    borderRadius: 6,
                    cursor: 'pointer',
                    fontSize: 12
                  }}
                >
                  Details
                </button>
              </div>
            </div>
          ))}
        </div>
        
        {filteredVMs.length === 0 && (
          <div style={{ textAlign: 'center', padding: 60, color: '#64b5f6' }}>
            <h2 style={{ color: '#00e5ff' }}>No assets found</h2>
            <p>Try adjusting your search or filters</p>
          </div>
        )}
      </div>
    </div>
  );
}
