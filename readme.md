# 🛡️ Cybersec Threat Detection System

> An autonomous AI-powered Security Operations Center (SOC) built with Microsoft AutoGen multi-agent framework. Six specialized AI agents work together to detect, analyze, and respond to cybersecurity threats in real time.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![AutoGen](https://img.shields.io/badge/AutoGen-0.4-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)
![Streamlit](https://img.shields.io/badge/Streamlit-1.40-FF4B4B)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Deploy](https://img.shields.io/badge/Deploy-Render-purple)

---

## 🌍 Live Demo

| Service | URL |
|---|---|
| 🔌 REST API | `https://cybersec-threat-detection.onrender.com` |
| 📊 Dashboard | `https://cybersec-dashboard.onrender.com` |
| 📖 API Docs | `https://cybersec-threat-detection.onrender.com/docs` |

---

## 🤖 How It Works

Six AI agents collaborate in a pipeline to analyze security logs:

```
Raw Logs → Log Analyzer → Threat Classifier → IOC Enrichment
                                                      ↓
          Incident Report ← Report Writer ← Auto Responder ← Threat Hunter
```

| Agent | Role |
|---|---|
| 🔍 Log Analyzer | Parses and normalizes raw security logs |
| 🎯 Threat Classifier | Classifies threat type and severity using MITRE ATT&CK |
| 🌐 IOC Enrichment | Checks IPs and hashes against VirusTotal and AbuseIPDB |
| 🕵️ Threat Hunter | Deep dives for hidden attack patterns and lateral movement |
| 🛡️ Auto Responder | Generates automated response and containment actions |
| 📄 Report Writer | Produces a full professional incident report |

---

## ✨ Features

- 🤖 **Multi-agent AI pipeline** — 6 specialized AutoGen agents working autonomously
- 🌐 **Real threat intelligence** — Live lookups via VirusTotal and AbuseIPDB APIs
- ⚡ **Fast inference** — Powered by Groq (Llama 3.3 70B)
- 📊 **Web dashboard** — Upload logs and visualize threats via Streamlit
- 🔌 **REST API** — Integrate into any app via FastAPI endpoints
- 🐳 **Docker ready** — One command to run everything locally
- 🆓 **100% free to run** — Uses only free tier APIs and services

---

## 🏗️ Tech Stack

| Layer | Technology |
|---|---|
| Agent Framework | Microsoft AutoGen 0.4 |
| LLM | Groq API (Llama 3.3 70B) |
| Threat Intel | VirusTotal API + AbuseIPDB API |
| Backend | FastAPI + Uvicorn |
| Frontend | Streamlit + Plotly |
| Containerization | Docker + Docker Compose |
| Deployment | Render.com |
| Language | Python 3.11 |

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/rithik-06/cybersec-threat-detection.git
cd cybersec-threat-detection
```

### 2. Create virtual environment
```bash
python3 -m venv venv --without-pip
source venv/bin/activate
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py
rm get-pip.py
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Set up environment variables
```bash
cp .env.example .env
```

Edit `.env` and add your API keys:
```env
GROQ_API_KEY=your_groq_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
MODEL_NAME=llama-3.3-70b-versatile
MAX_TOKENS=1000
```

### 5. Run the pipeline
```bash
python3 main.py
```

### 6. Start the API
```bash
python3 api.py
```

### 7. Start the Dashboard
```bash
streamlit run dashboard.py
```

---

## 🐳 Run with Docker

```bash
docker compose up --build
```

- API → `http://localhost:8000`
- Dashboard → `http://localhost:8501`

---

## 🔌 API Usage

### Analyze logs
```bash
curl -X POST https://cybersec-threat-detection.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"logs": [{"timestamp": "2026-03-17T10:23:11", "source_ip": "185.220.101.45", "event_type": "failed_login", "count": 87, "message": "Multiple failed SSH login attempts"}]}'
```

### Check an IP
```bash
curl -X POST https://cybersec-threat-detection.onrender.com/check/ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "185.220.101.45"}'
```

### Check a file hash
```bash
curl -X POST https://cybersec-threat-detection.onrender.com/check/hash \
  -H "Content-Type: application/json" \
  -d '{"file_hash": "d41d8cd98f00b204e9800998ecf8427e"}'
```

### List all reports
```bash
curl https://cybersec-threat-detection.onrender.com/reports
```

---

## 📁 Project Structure

```
cybersec-threat-detection/
├── agents/
│   ├── log_analyzer.py        # Agent 1 — parses logs
│   ├── threat_classifier.py   # Agent 2 — classifies threats
│   ├── ioc_enrichment.py      # Agent 3 — threat intel lookups
│   ├── threat_hunter.py       # Agent 4 — deep investigation
│   ├── auto_responder.py      # Agent 5 — automated response
│   ├── report_writer.py       # Agent 6 — incident reports
│   └── orchestrator.py        # Coordinates all agents
├── config/
│   └── settings.py            # Configuration and LLM setup
├── utils/
│   ├── logger.py              # Colored logging
│   └── helpers.py             # Utility functions
├── data/
│   ├── sample_logs.json       # Sample logs for testing
│   ├── test_brute_force.json  # Brute force attack test
│   ├── test_malware.json      # Malware infection test
│   └── test_apt.json          # APT attack test
├── static/
│   └── index.html             # API landing page
├── logs/
│   └── reports/               # Generated incident reports
├── main.py                    # CLI entry point
├── api.py                     # FastAPI backend
├── dashboard.py               # Streamlit frontend
├── Dockerfile                 # Docker configuration
├── docker-compose.yml         # Multi-service Docker setup
└── requirements.txt           # Python dependencies
```

---

## 🔑 Free API Keys Setup

| API | Free Tier | Sign Up |
|---|---|---|
| Groq | 14,400 req/day | [console.groq.com](https://console.groq.com) |
| VirusTotal | 4 lookups/min | [virustotal.com](https://www.virustotal.com) |
| AbuseIPDB | 1,000 checks/day | [abuseipdb.com](https://www.abuseipdb.com) |

---

## 📊 Sample Output

```
============================================================
         THREAT DETECTION COMPLETE
============================================================
  Incident ID    : INC-20260317-0001
  Threat Type    : Multi-Vector Attack
  Severity       : CRITICAL (9/10)
  Attack Stage   : INITIAL_ACCESS
  Confirmed      : True
  Containment    : PARTIALLY_CONTAINED
  Escalation     : True
  Report saved   : logs/reports/INC-20260317-0001.json
============================================================
```

---

## 🗺️ Roadmap

- [x] 6 AutoGen agents pipeline
- [x] Real threat intelligence APIs
- [x] FastAPI REST backend
- [x] Streamlit web dashboard
- [x] Docker containerization
- [x] Render.com deployment
- [ ] GitHub Actions CI/CD
- [ ] ChromaDB memory for past incidents
- [ ] Email/Slack alerting
- [ ] Support for more log formats (Nginx, Apache, Windows)

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 👨‍💻 Author

**Rithik Tiwari**
- GitHub: [@rithik-06](https://github.com/rithik-06)

---

## 📄 License

This project is licensed under the MIT License.

---

## ⭐ Support

If this project helped you, please give it a ⭐ on GitHub!