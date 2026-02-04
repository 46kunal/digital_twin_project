# Digital Twin Based Network Security Scanner (Aegis)

This repository contains the implementation of a Digital Twin–based network security scanner developed as part of an academic research project.

## Project Overview
The system integrates Nmap-based active scanning with a backend REST API and a real-time WebSocket interface. Scan results are stored persistently and visualized through a web-based dashboard.

## Technology Stack
- Backend: Python, Flask, SQLAlchemy
- Frontend: React, JavaScript
- Scanning Engine: Nmap
- Database: SQLite (development)

## Key Features
- Network host discovery and port scanning
- Digital twin representation of assets and vulnerabilities
- Real-time scan progress via WebSockets
- PDF-based vulnerability reporting

This repository serves as the reference implementation for the research paper titled:
"A Digital-Twin Based Network Security Scanner with Real-Time Visualization".
