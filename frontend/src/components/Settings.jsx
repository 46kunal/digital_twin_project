import React, { useState, useContext } from 'react';
import Sidebar from './Sidebar';
import { AuthContext } from '../context/AuthContext';
import api from '../services/api';

export default function Settings() {
  const { user } = useContext(AuthContext);
  const [activeTab, setActiveTab] = useState('general');
  const [platformName, setPlatformName] = useState('Aegis Security Platform');
  const [timezone, setTimezone] = useState('UTC');
  const [language, setLanguage] = useState('English');
  
  // User management
  const [users, setUsers] = useState([
    { id: 1, username: 'admin', email: 'admin@aegis.local', role: 'Admin', status: 'Active' },
    { id: 2, username: 'analyst1', email: 'analyst@aegis.local', role: 'Analyst', status: 'Active' }
  ]);
  const [showAddUser, setShowAddUser] = useState(false);
  const [newUser, setNewUser] = useState({ username: '', email: '', password: '', role: 'Viewer' });

  const handleSaveSettings = () => {
    alert('Settings saved successfully!');
  };

  const handleAddUser = (e) => {
    e.preventDefault();
    // In real implementation, call API
    const user = {
      id: users.length + 1,
      ...newUser,
      status: 'Active'
    };
    setUsers([...users, user]);
    setNewUser({ username: '', email: '', password: '', role: 'Viewer' });
    setShowAddUser(false);
    alert('User added successfully!');
  };

  const handleDeleteUser = (userId) => {
    if (window.confirm('Are you sure you want to delete this user?')) {
      setUsers(users.filter(u => u.id !== userId));
      alert('User deleted successfully!');
    }
  };

  const tabs = [
    { id: 'general', label: 'General', icon: '⚙️' },
    { id: 'users', label: 'Users & Roles', icon: '👥' },
    { id: 'security', label: 'Security', icon: '🔒' },
    { id: 'notifications', label: 'Notifications', icon: '🔔' },
    { id: 'api', label: 'API Keys', icon: '🔑' }
  ];

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
          Settings
        </h1>

        <div style={{ display: 'flex', gap: 30 }}>
          {/* Sidebar Tabs */}
          <div style={{ width: 220 }}>
            {tabs.map(tab => (
              <div
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  padding: '12px 16px',
                  margin: '5px 0',
                  background: activeTab === tab.id
                    ? 'linear-gradient(135deg, rgba(0, 229, 255, 0.15) 0%, rgba(0, 145, 234, 0.08) 100%)'
                    : 'transparent',
                  border: activeTab === tab.id ? '1px solid rgba(0, 229, 255, 0.3)' : '1px solid transparent',
                  borderRadius: 10,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  transition: 'all 0.3s'
                }}
                onMouseEnter={(e) => {
                  if (activeTab !== tab.id) {
                    e.currentTarget.style.background = 'rgba(0, 229, 255, 0.05)';
                  }
                }}
                onMouseLeave={(e) => {
                  if (activeTab !== tab.id) {
                    e.currentTarget.style.background = 'transparent';
                  }
                }}
              >
                <span style={{ fontSize: 18 }}>{tab.icon}</span>
                <span style={{
                  color: activeTab === tab.id ? '#00e5ff' : '#90caf9',
                  fontWeight: activeTab === tab.id ? 600 : 400,
                  fontSize: 14
                }}>
                  {tab.label}
                </span>
              </div>
            ))}
          </div>

          {/* Content Area */}
          <div style={{ flex: 1 }}>
            {/* General Settings */}
            {activeTab === 'general' && (
              <div style={{
                background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.05) 0%, rgba(0, 145, 234, 0.02) 100%)',
                border: '1px solid rgba(0, 229, 255, 0.15)',
                borderRadius: 15,
                padding: 30,
                backdropFilter: 'blur(10px)'
              }}>
                <h2 style={{ margin: '0 0 25px 0', color: '#00e5ff', fontSize: 22 }}>General Settings</h2>

                <div style={{ marginBottom: 20 }}>
                  <label style={{ display: 'block', marginBottom: 8, color: '#90caf9', fontSize: 14 }}>
                    Platform Name
                  </label>
                  <input
                    type="text"
                    value={platformName}
                    onChange={(e) => setPlatformName(e.target.value)}
                    style={{
                      width: '100%',
                      padding: 12,
                      background: 'rgba(0, 0, 0, 0.3)',
                      border: '1px solid rgba(0, 229, 255, 0.3)',
                      borderRadius: 8,
                      color: '#fff',
                      fontSize: 14
                    }}
                  />
                </div>

                <div style={{ marginBottom: 20 }}>
                  <label style={{ display: 'block', marginBottom: 8, color: '#90caf9', fontSize: 14 }}>
                    Timezone
                  </label>
                  <select
                    value={timezone}
                    onChange={(e) => setTimezone(e.target.value)}
                    style={{
                      width: '100%',
                      padding: 12,
                      background: 'rgba(0, 0, 0, 0.3)',
                      border: '1px solid rgba(0, 229, 255, 0.3)',
                      borderRadius: 8,
                      color: '#fff',
                      fontSize: 14,
                      cursor: 'pointer'
                    }}
                  >
                    <option value="UTC">UTC</option>
                    <option value="America/New_York">Eastern Time (US)</option>
                    <option value="Europe/London">London (GMT)</option>
                    <option value="Asia/Kolkata">India (IST)</option>
                    <option value="Asia/Tokyo">Tokyo (JST)</option>
                  </select>
                </div>

                <div style={{ marginBottom: 25 }}>
                  <label style={{ display: 'block', marginBottom: 8, color: '#90caf9', fontSize: 14 }}>
                    Language
                  </label>
                  <select
                    value={language}
                    onChange={(e) => setLanguage(e.target.value)}
                    style={{
                      width: '100%',
                      padding: 12,
                      background: 'rgba(0, 0, 0, 0.3)',
                      border: '1px solid rgba(0, 229, 255, 0.3)',
                      borderRadius: 8,
                      color: '#fff',
                      fontSize: 14,
                      cursor: 'pointer'
                    }}
                  >
                    <option value="English">English</option>
                    <option value="Spanish">Spanish</option>
                    <option value="French">French</option>
                    <option value="German">German</option>
                  </select>
                </div>

                <button
                  onClick={handleSaveSettings}
                  style={{
                    padding: '12px 24px',
                    background: 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
                    color: '#001e3c',
                    border: 'none',
                    borderRadius: 8,
                    cursor: 'pointer',
                    fontWeight: 600,
                    fontSize: 14
                  }}
                >
                  Save Changes
                </button>
              </div>
            )}

            {/* Users & Roles */}
            {activeTab === 'users' && (
              <div style={{
                background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.05) 0%, rgba(0, 145, 234, 0.02) 100%)',
                border: '1px solid rgba(0, 229, 255, 0.15)',
                borderRadius: 15,
                padding: 30,
                backdropFilter: 'blur(10px)'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 25 }}>
                  <h2 style={{ margin: 0, color: '#00e5ff', fontSize: 22 }}>User Management</h2>
                  <button
                    onClick={() => setShowAddUser(!showAddUser)}
                    style={{
                      padding: '10px 20px',
                      background: 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
                      color: '#001e3c',
                      border: 'none',
                      borderRadius: 8,
                      cursor: 'pointer',
                      fontWeight: 600,
                      fontSize: 13
                    }}
                  >
                    ➕ Add User
                  </button>
                </div>

                {/* Add User Form */}
                {showAddUser && (
                  <div style={{
                    background: 'rgba(0, 0, 0, 0.2)',
                    padding: 20,
                    borderRadius: 10,
                    marginBottom: 20,
                    border: '1px solid rgba(0, 229, 255, 0.2)'
                  }}>
                    <h3 style={{ margin: '0 0 15px 0', color: '#00e5ff', fontSize: 16 }}>Add New User</h3>
                    <form onSubmit={handleAddUser}>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 15, marginBottom: 15 }}>
                        <input
                          type="text"
                          placeholder="Username"
                          value={newUser.username}
                          onChange={(e) => setNewUser({...newUser, username: e.target.value})}
                          required
                          style={{
                            padding: 10,
                            background: 'rgba(0, 0, 0, 0.3)',
                            border: '1px solid rgba(0, 229, 255, 0.3)',
                            borderRadius: 8,
                            color: '#fff',
                            fontSize: 14
                          }}
                        />
                        <input
                          type="email"
                          placeholder="Email"
                          value={newUser.email}
                          onChange={(e) => setNewUser({...newUser, email: e.target.value})}
                          required
                          style={{
                            padding: 10,
                            background: 'rgba(0, 0, 0, 0.3)',
                            border: '1px solid rgba(0, 229, 255, 0.3)',
                            borderRadius: 8,
                            color: '#fff',
                            fontSize: 14
                          }}
                        />
                        <input
                          type="password"
                          placeholder="Password"
                          value={newUser.password}
                          onChange={(e) => setNewUser({...newUser, password: e.target.value})}
                          required
                          style={{
                            padding: 10,
                            background: 'rgba(0, 0, 0, 0.3)',
                            border: '1px solid rgba(0, 229, 255, 0.3)',
                            borderRadius: 8,
                            color: '#fff',
                            fontSize: 14
                          }}
                        />
                        <select
                          value={newUser.role}
                          onChange={(e) => setNewUser({...newUser, role: e.target.value})}
                          style={{
                            padding: 10,
                            background: 'rgba(0, 0, 0, 0.3)',
                            border: '1px solid rgba(0, 229, 255, 0.3)',
                            borderRadius: 8,
                            color: '#fff',
                            fontSize: 14,
                            cursor: 'pointer'
                          }}
                        >
                          <option value="Viewer">Viewer</option>
                          <option value="Analyst">Analyst</option>
                          <option value="Admin">Admin</option>
                        </select>
                      </div>
                      <div style={{ display: 'flex', gap: 10 }}>
                        <button
                          type="submit"
                          style={{
                            padding: '10px 20px',
                            background: 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
                            color: '#001e3c',
                            border: 'none',
                            borderRadius: 8,
                            cursor: 'pointer',
                            fontWeight: 600,
                            fontSize: 13
                          }}
                        >
                          Create User
                        </button>
                        <button
                          type="button"
                          onClick={() => setShowAddUser(false)}
                          style={{
                            padding: '10px 20px',
                            background: 'transparent',
                            color: '#fff',
                            border: '1px solid rgba(255, 255, 255, 0.3)',
                            borderRadius: 8,
                            cursor: 'pointer',
                            fontSize: 13
                          }}
                        >
                          Cancel
                        </button>
                      </div>
                    </form>
                  </div>
                )}

                {/* Users Table */}
                <table style={{ width: '100%', borderCollapse: 'separate', borderSpacing: '0 8px' }}>
                  <thead>
                    <tr style={{ color: '#64b5f6', fontSize: 12, textTransform: 'uppercase' }}>
                      <th style={{ textAlign: 'left', padding: '12px 15px' }}>Username</th>
                      <th style={{ textAlign: 'left', padding: '12px 15px' }}>Email</th>
                      <th style={{ textAlign: 'left', padding: '12px 15px' }}>Role</th>
                      <th style={{ textAlign: 'left', padding: '12px 15px' }}>Status</th>
                      <th style={{ textAlign: 'center', padding: '12px 15px' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map(user => (
                      <tr key={user.id} style={{
                        background: 'rgba(0, 229, 255, 0.03)',
                        border: '1px solid rgba(0, 229, 255, 0.1)'
                      }}>
                        <td style={{ padding: 15, borderRadius: '8px 0 0 8px', color: '#fff' }}>{user.username}</td>
                        <td style={{ padding: 15, color: '#90caf9' }}>{user.email}</td>
                        <td style={{ padding: 15 }}>
                          <span style={{
                            padding: '6px 14px',
                            background: user.role === 'Admin' ? 'rgba(255, 107, 107, 0.15)' :
                                       user.role === 'Analyst' ? 'rgba(0, 229, 255, 0.15)' : 'rgba(255, 211, 61, 0.15)',
                            border: `1px solid ${user.role === 'Admin' ? 'rgba(255, 107, 107, 0.3)' :
                                                user.role === 'Analyst' ? 'rgba(0, 229, 255, 0.3)' : 'rgba(255, 211, 61, 0.3)'}`,
                            borderRadius: 20,
                            color: user.role === 'Admin' ? '#ff6b6b' :
                                   user.role === 'Analyst' ? '#00e5ff' : '#ffd93d',
                            fontSize: 12,
                            fontWeight: 600
                          }}>
                            {user.role}
                          </span>
                        </td>
                        <td style={{ padding: 15, color: '#51cf66' }}>{user.status}</td>
                        <td style={{ padding: 15, borderRadius: '0 8px 8px 0', textAlign: 'center' }}>
                          <button
                            onClick={() => handleDeleteUser(user.id)}
                            disabled={user.username === 'admin'}
                            style={{
                              padding: '6px 12px',
                              background: user.username === 'admin' ? '#666' : 'transparent',
                              color: user.username === 'admin' ? '#ccc' : '#ff6b6b',
                              border: `1px solid ${user.username === 'admin' ? '#666' : '#ff6b6b'}`,
                              borderRadius: 6,
                              cursor: user.username === 'admin' ? 'not-allowed' : 'pointer',
                              fontSize: 12
                            }}
                          >
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Other tabs coming soon */}
            {activeTab !== 'general' && activeTab !== 'users' && (
              <div style={{
                background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.05) 0%, rgba(0, 145, 234, 0.02) 100%)',
                border: '1px solid rgba(0, 229, 255, 0.15)',
                borderRadius: 15,
                padding: 60,
                backdropFilter: 'blur(10px)',
                textAlign: 'center'
              }}>
                <h2 style={{ color: '#00e5ff', fontSize: 24, marginBottom: 10 }}>Coming Soon</h2>
                <p style={{ color: '#64b5f6', fontSize: 14 }}>This section is under development</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
