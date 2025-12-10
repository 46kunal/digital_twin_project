# Aegis Security Platform - User Guide

## Getting Started

### 1. Login
- Default admin credentials: `admin` / `admin`
- Change password immediately in Settings

### 2. Discover Network Assets
1. Click "🔍 Discover VMs" button
2. Enter your network range (e.g., `192.168.56.0/24`)
3. Click "Start"
4. Wait for discovery to complete

### 3. Run Security Scans

#### Scan Modes:
- **Fast** (≈2min): Quick check for critical vulnerabilities
- **Medium** (≈6min): Balanced scan with common ports
- **Full** (≈15min): Deep scan - all ports & services

#### Steps:
1. Go to Dashboard → Asset Inventory
2. Click "Scan" button on any VM
3. Select scan mode
4. Click "Start Scan"
5. Monitor progress in real-time

### 4. View Results
- **Dashboard**: Overall statistics
- **Scans**: Detailed scan history
- **Vulnerabilities**: Complete vulnerability index
- **Reports**: Generate & download PDF reports

### 5. User Management (Admin Only)
1. Go to Settings → Users & Roles
2. Click "➕ Add User"
3. Fill in details and assign role:
   - **Viewer**: Read-only access
   - **Analyst**: Can run scans
   - **Admin**: Full control

## Best Practices

### Security
- Change default passwords
- Use strong passwords (12+ characters)
- Limit Admin role to trusted users
- Review scan logs regularly

### Scanning
- Start with **Fast** scans to identify critical issues
- Use **Full** scans monthly for comprehensive audits
- Schedule scans during off-peak hours
- Export reports for compliance records

### Troubleshooting

#### "nmap not found" Error

---

## 5️⃣ Generating Reports

### PDF Reports
1. Navigate to **Reports** page
2. Find the completed scan you want to report on
3. Click **"📥 Download PDF"**
4. Report includes:
   - Executive summary
   - Severity breakdown
   - Detailed vulnerability list
   - Remediation recommendations

### Bulk Reports
- Click **"📊 Generate Bulk Report"** to combine multiple scans
- Useful for monthly security reviews

---

## 6️⃣ User Management (Admin Only)

### Adding Users
1. Go to **Settings** → **Users & Roles**
2. Click **"➕ Add User"**
3. Fill in:
   - Username
   - Email
   - Password
   - Role (Viewer/Analyst/Admin)
4. Click **"Create User"**

### User Roles

| Role | Permissions |
|------|-------------|
| **Viewer** | View dashboards, scans, vulnerabilities (read-only) |
| **Analyst** | Everything Viewer can do + run scans + generate reports |
| **Admin** | Full control including user management and system settings |

---

## 7️⃣ Best Practices

### Security
✅ Change default passwords immediately
✅ Use strong passwords (12+ characters, mixed case, numbers, symbols)
✅ Limit Admin role to 1-2 trusted users
✅ Review scan logs regularly
✅ Export reports for compliance records

### Scanning Strategy
✅ **Daily:** Fast scans on critical assets
✅ **Weekly:** Medium scans on all production systems
✅ **Monthly:** Full scans for comprehensive audits
✅ **After Changes:** Scan any system after updates/patches

### Performance
✅ Use smaller CIDR ranges (/29, /30) for faster discovery
✅ Schedule heavy scans during off-peak hours
✅ Avoid running multiple full scans simultaneously

---

## 8️⃣ Troubleshooting

### "nmap not found" Error


### Discovery Not Finding VMs

**Check:**

- Are VMs powered on?

- Correct network adapter (Host-Only)?

- Firewall not blocking ICMP?



**Solution:**



### Slow Scan Performance

**Possible causes:**

- Network congestion

- Target system slow to respond

- Full scan on large network



**Solutions:**

- Use Fast mode instead

- Reduce CIDR range

- Scan during off-peak hours



### WebSocket Connection Failed

**Check:**

- Backend server is running

- Port 5000 is accessible

- No firewall blocking WebSocket



**Solution:**


---

## 9️⃣ Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Esc` | Close any modal/popup |
| `F5` | Refresh current page |
| `Ctrl + K` | Quick search (coming soon) |

---

## 🔟 System Requirements

### Server (Backend)
- **OS:** Kali Linux / Ubuntu / Debian
- **RAM:** 2GB minimum, 4GB recommended
- **Disk:** 10GB free space
- **Network:** Host-only or NAT network access
- **Software:** Python 3.8+, nmap, SQLite3

### Client (Frontend)
- **Browser:** Chrome 90+, Firefox 88+, Edge 90+
- **Network:** Access to backend server IP

---

## 📞 Support

### Getting Help
1. Check this user guide first
2. Review error messages in browser console (F12)
3. Check backend logs: `tail -f backend/app.log`
4. Contact your system administrator

### Reporting Bugs
Include:
- What you were trying to do
- What happened instead
- Error messages (screenshots helpful)
- Browser and OS version

---

## 📚 Additional Resources

### Learning More
- **CVSS Calculator:** https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
- **Nmap Documentation:** https://nmap.org/book/man.html
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/

### Security Standards
- ISO 27001
- NIST Cybersecurity Framework
- CIS Controls

---

**Version:** 1.0.0  
**Last Updated:** December 4, 2025  
**Platform:** Aegis Security - Digital Twin Vulnerability Scanner
