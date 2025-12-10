import { io } from 'socket.io-client';

const SOCKET_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

let socket = null;

export const initSocket = () => {
  if (!socket) {
    socket = io(SOCKET_URL, {
      path: '/socket.io',           // important when backend not on same origin
      transports: ['websocket'],    // force websocket first
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      withCredentials: false,
    });

    socket.on('connect', () => {
      console.log('WebSocket connected', socket.id);
    });

    socket.on('connect_error', (err) => {
      console.error('WebSocket connect_error:', err.message);
    });

    socket.on('disconnect', (reason) => {
      console.log('WebSocket disconnected:', reason);
    });

    socket.on('connection_response', (data) => {
      console.log('Connection response:', data);
    });
  }

  return socket;
};

export const getSocket = () => socket;

export const disconnectSocket = () => {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
};
