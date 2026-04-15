# 🔐 Flask Security Project — 

**Advanced Security Audits & Final Deployment Security**  
**Student:** Shahzaib | Government College University Faisalabad (GCUF)  
**Project Duration:** Week 4 → Week 5 → Week 6  

---

## 📋 Project Overview

A Python Flask web application that was progressively hardened over three weeks using real-world security tools and techniques used by professional penetration testers and security engineers.

| Week | Focus | Key Tools |
|------|-------|-----------|
| Week 4 | Proactive Security Measures | Flask-Limiter, Flask-Talisman, Flask-CORS |
| Week 5 | Ethical Hacking & Vulnerability Fixes | Nmap, SQLMap, Manual Testing |
| Week 6 | Security Audits & Docker Deployment | OWASP ZAP, Burp Suite, Docker |

---

## 🏆 Final Security Score

| Metric | Result | Status |
|--------|--------|--------|
| OWASP Top 10 Compliance | 89% (8/9 applicable) | ✅ PASS |
| ZAP Scan — High Risk Issues | 0 High, 4 Medium | ✅ SECURE |
| Penetration Test Attack Vectors | 8/8 Blocked | ✅ SECURE |
| Docker Security Best Practices | 5/5 Implemented | ✅ PASS |

---

## 🛠️ Tools & Environment

| Tool | Purpose | Version |
|------|---------|---------|
| OWASP ZAP | Automated vulnerability scanning | Latest |
| Burp Suite | Passive crawl & penetration testing | Community 2026.3.2 |
| Nmap | Network reconnaissance | 7.98 |
| Docker Desktop | Container deployment | 4.68.0 |
| Python Flask | Target web application | 3.x / Python 3.14.2 |
| Windows 10 | Testing environment | OS |

---

## 🚀 Getting Started

### Option 1 — Run with Docker (Recommended)

```bash
# Build the image
docker build -t gcuf-security-app .

# Run the container
docker run -p 3000:3000 \
  -e SECRET_KEY=your-secret-key \
  -e API_KEY=your-api-key \
  gcuf-security-app
```

### Option 2 — Run Locally

```bash
# Clone the repo
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

App will be available at: **http://127.0.0.1:3000**

---

## 📁 Project Structure

```
├── app.py              # Main Flask application (security hardened)
├── Dockerfile          # Docker container with 5 security best practices
├── requirements.txt    # Locked dependencies (OWASP A06 fix)
├── security.log        # Auto-generated security event log
├── database.db         # Auto-generated SQLite database
└── README.md           # This file
```

---

## 🔒 Security Features Implemented

### Week 4 — Proactive Defense

- **Rate Limiting** — Flask-Limiter blocks brute force (5 req/min on login)
- **API Key Authentication** — Custom decorator protects `/system_info`, `/os_info`
- **CORS Protection** — Flask-CORS blocks external origins
- **Security Headers** — Flask-Talisman adds CSP, HSTS, X-Frame-Options

### Week 5 — Vulnerability Fixes

- **SQL Injection Fix** — Prepared statements (`?` placeholders) on all queries
- **CSRF Fix** — Flask-WTF CSRF tokens on all forms
- **Reconnaissance** — Nmap scan results documented

### Week 6 — Audit & Deployment

- **OWASP ZAP Scan** — 11 alerts found, 0 High risk
- **OWASP Top 10 Compliance** — 89% compliant (8/9 applicable controls)
- **Docker Security** — Non-root user, slim image, no-cache install, minimal ports
- **Final Pen Test** — 244 pages mapped, 8 attack vectors all blocked

---

## 🌐 API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | None | App status |
| `/register` | GET/POST | None | User registration |
| `/login` | GET/POST | None | User login (rate limited) |
| `/logout` | GET | Session | Logout |
| `/account` | GET/POST | Session | Account info |
| `/change_password` | GET/POST | Session + CSRF | Change password |
| `/search` | GET/POST | Session | Search users |
| `/admin` | GET | Admin role | Admin panel |
| `/system_info` | GET | API Key | System information |
| `/os_info` | GET | API Key | OS information |

---

## 🐋 Docker Security Best Practices

```dockerfile
FROM python:3.11-slim          # ✅ Slim image — reduced attack surface
RUN useradd -m -u 1000 appuser # ✅ Non-root user — privilege escalation prevention
RUN pip install --no-cache-dir # ✅ No-cache — no stale packages
RUN chown -R appuser:appuser   # ✅ File ownership — proper access control
EXPOSE 3000                    # ✅ Minimal ports — only what's needed
```

---

## 📊 OWASP ZAP Scan Results (Week 6)

| Risk Level | Count | Action |
|------------|-------|--------|
| 🔴 High | 0 | None needed |
| 🟠 Medium | 4 | Under review |
| 🟡 Low | 3 | Monitored |
| 🔵 Info | 4 | No action needed |

---

## ✅ OWASP Top 10 Compliance

| # | Category | Status |
|---|----------|--------|
| A01 | Broken Access Control | ✅ PASS |
| A02 | Cryptographic Failures | ⚠️ PARTIAL |
| A03 | SQL Injection | ✅ PASS |
| A04 | Insecure Design (CSRF) | ✅ PASS |
| A05 | Security Misconfiguration | ✅ PASS |
| A06 | Vulnerable Components | ✅ PASS |
| A07 | Auth & Session Failures | ✅ PASS |
| A08 | Software & Data Integrity | ✅ PASS |
| A09 | Security Logging | ✅ PASS |
| A10 | SSRF | N/A |

**Score: 89% (8/9 applicable controls passed)**

---

## 🔬 Penetration Testing Results (Week 6)

| # | Attack Vector | Tool | Result |
|---|---------------|------|--------|
| 1 | SQL Injection — Search | SQLMap | ✅ BLOCKED |
| 2 | SQL Injection — Login | Manual | ✅ BLOCKED |
| 3 | Brute Force Login | Rapid requests | ✅ BLOCKED |
| 4 | CSRF Attack | Manual PoC | ✅ BLOCKED |
| 5 | API Without Key | curl | ✅ BLOCKED |
| 6 | XSS via Chat | Manual | ✅ BLOCKED |
| 7 | Admin Access | Direct URL | ✅ BLOCKED |
| 8 | CORS External Origin | HTML file | ✅ BLOCKED |

**Result: 8/8 attack vectors successfully blocked**

---

## 📝 License

Academic project — Government College University Faisalabad (GCUF) — 2026
