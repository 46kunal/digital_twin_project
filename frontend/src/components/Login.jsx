import React, { useState, useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await login(username, password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.response?.data?.msg || 'Login failed');
    }
  };

  return (
    <div style={{ 
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0a1929 0%, #001e3c 100%)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center'
    }}>
      <div style={{
        width: 450,
        background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.08) 0%, rgba(0, 145, 234, 0.04) 100%)',
        backdropFilter: 'blur(20px)',
        border: '1px solid rgba(0, 229, 255, 0.2)',
        borderRadius: 20,
        padding: 40,
        boxShadow: '0 8px 32px rgba(0, 229, 255, 0.15)'
      }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 40 }}>
          <div style={{
            width: 70,
            height: 70,
            background: 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
            borderRadius: 15,
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 32,
            boxShadow: '0 4px 20px rgba(0, 229, 255, 0.4)',
            marginBottom: 20
          }}>
            🛡️
          </div>
          <h2 style={{
            margin: 0,
            fontSize: 28,
            fontWeight: 700,
            background: 'linear-gradient(90deg, #00e5ff 0%, #fff 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>
            Aegis
          </h2>
          <p style={{ margin: '5px 0 0 0', color: '#64b5f6', fontSize: 14 }}>Security Platform</p>
        </div>

        <h3 style={{ margin: '0 0 30px 0', color: '#fff', fontSize: 20, textAlign: 'center' }}>Login</h3>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', marginBottom: 8, color: '#90caf9', fontSize: 13 }}>
              Email
            </label>
            <input
              type="text"
              placeholder="Enter your email here"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{ 
                width: '100%',
                padding: 14,
                background: 'rgba(0, 0, 0, 0.3)',
                border: '1px solid rgba(0, 229, 255, 0.3)',
                borderRadius: 10,
                color: '#fff',
                fontSize: 14,
                outline: 'none',
                transition: 'border 0.3s'
              }}
              onFocus={(e) => e.target.style.border = '1px solid #00e5ff'}
              onBlur={(e) => e.target.style.border = '1px solid rgba(0, 229, 255, 0.3)'}
            />
          </div>

          <div style={{ marginBottom: 25 }}>
            <label style={{ display: 'block', marginBottom: 8, color: '#90caf9', fontSize: 13 }}>
              Password
            </label>
            <input
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{ 
                width: '100%',
                padding: 14,
                background: 'rgba(0, 0, 0, 0.3)',
                border: '1px solid rgba(0, 229, 255, 0.3)',
                borderRadius: 10,
                color: '#fff',
                fontSize: 14,
                outline: 'none',
                transition: 'border 0.3s'
              }}
              onFocus={(e) => e.target.style.border = '1px solid #00e5ff'}
              onBlur={(e) => e.target.style.border = '1px solid rgba(0, 229, 255, 0.3)'}
            />
          </div>

          <button 
            type="submit"
            style={{ 
              width: '100%',
              padding: 14,
              background: 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)',
              color: '#001e3c',
              border: 'none',
              borderRadius: 10,
              fontSize: 15,
              fontWeight: 700,
              cursor: 'pointer',
              boxShadow: '0 4px 20px rgba(0, 229, 255, 0.3)',
              transition: 'transform 0.2s'
            }}
            onMouseEnter={(e) => e.currentTarget.style.transform = 'translateY(-2px)'}
            onMouseLeave={(e) => e.currentTarget.style.transform = 'translateY(0)'}
          >
            Sign In
          </button>
        </form>

        {error && (
          <p style={{ 
            color: '#ff6b6b', 
            marginTop: 15, 
            textAlign: 'center',
            fontSize: 13,
            background: 'rgba(255, 107, 107, 0.1)',
            padding: 10,
            borderRadius: 8,
            border: '1px solid rgba(255, 107, 107, 0.3)'
          }}>
            {error}
          </p>
        )}

        <p style={{ 
          textAlign: 'center', 
          marginTop: 20, 
          color: '#64b5f6', 
          fontSize: 13,
          cursor: 'pointer'
        }}>
          Forgot your password?
        </p>
      </div>
    </div>
  );
}
