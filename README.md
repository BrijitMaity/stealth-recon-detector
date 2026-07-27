# AI-Powered Stealth Reconnaissance Detection System

> **Industrial-Grade Cybersecurity Monitoring** — Multi-layer threat detection combining Deep Packet Inspection, Machine Learning (Random Forest), and GenAI (DistilBERT) in a real-time packet monitoring pipeline.

![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue)
![License](https://img.shields.io/badge/License-Academic-green)
![Status](https://img.shields.io/badge/Status-Production--Ready-brightgreen)

---

## Architecture

```
[Network Packet / Simulated Packet]
       |
       v
[monitor.py] ─── orchestrates all components
       |
       ├──> [firewall.py]      ─ IP blocking (Windows netsh / Linux iptables)
       |
       ├──> [dpi_analyzer.py]  ─ Regex-based Deep Packet Inspection
       |         ├── Layer 1: 10 DPI Signature Rules (SQLi, XSS, RCE, SSRF, XXE...)
       |         └── Layer 2: GenAI payload analysis for unknown patterns
       |
       ├──> [analyzer.py]      ─ ML + GenAI behavioral classification
       |         ├── Layer 3: Random Forest ML (10 real features)
       |         └── Layer 4: DistilBERT text classifier (or MockPipeline)
       |
       ├──> [logger.py]        ─ 120-column CSV + buffered I/O
       ├──> [state_manager.py] ─ SQLite state persistence (survives restarts)
       ├──> [dashboard.py]     ─ Flask + Socket.IO web dashboard (authenticated) + Prometheus
       └──> [report_generator.py] ─ HTML Security reports with MITRE ATT&CK mapping
```

## Detection Layers (Priority Order)

| Layer | Engine | Confidence | Description |
|-------|--------|------------|-------------|
| 1 | DPI Signatures | 90-99% | Regex patterns for SQLi, XSS, RCE, SSRF, XXE, Log4j, etc. |
| 2 | GenAI Payload | 85%+ | DistilBERT semantic analysis of unknown payloads |
| 3 | Random Forest ML | Variable | 10-feature behavioral model trained on 10K+ samples |
| 4 | Heuristic Fallback | Variable | Keyword-based threat detection |

## Quick Start

### Prerequisites
- Python 3.9+ (3.13 recommended)
- For LIVE mode: [Npcap](https://npcap.com) installed
- For REAL firewall: Run as Administrator (Windows) or root (Linux)

### Installation

```bash
# Clone the project
cd E:\gen_ai_sketch_detector\gen_ai_sketch_detector

# Create virtual environment
python -m venv venv

# Activate (Windows)
.\venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Optional: Install full AI mode (requires ~2-3 GB)
pip install torch transformers
```

### Run

```bash
# Simulation mode (recommended for testing / demo)
python monitor.py --simulate

# Live packet capture mode (requires Npcap + Admin)
python monitor.py
```

### Access Dashboard
Open browser → **http://127.0.0.1:5000**
- Default credentials: `admin` / `stealth2026`
- Override via `STEALTH_DASHBOARD_USER` and `STEALTH_DASHBOARD_PASS` env vars

## Configuration

All settings are configurable via environment variables. See [config.py](config.py) for the full list.

| Variable | Default | Description |
|----------|---------|-------------|
| `STEALTH_DASHBOARD_HOST` | `127.0.0.1` | Dashboard bind address |
| `STEALTH_DASHBOARD_PORT` | `5000` | Dashboard port |
| `STEALTH_DASHBOARD_USER` | `admin` | Dashboard login username |
| `STEALTH_DASHBOARD_PASS` | `stealth2026` | Dashboard login password |
| `STEALTH_ML_THRESHOLD` | `50.0` | ML confidence threshold (%) |
| `STEALTH_BLOCK_TTL` | `3600` | Auto-unblock after N seconds |
| `STEALTH_LOG_LEVEL` | `INFO` | Logging level |
| `STEALTH_THREAD_POOL` | `10` | Worker threads for packet processing |

## Output Files

| File | Description |
|------|-------------|
| `stealth_detection_logs.csv` | Primary event log (120 columns, auto-rotated at 200MB) |
| `stealth_detection_logs_cleaned.csv` | Auto-cleaned copy (background thread) |
| `stealth_detection_logs_cleaned.xlsx` | Excel export (if openpyxl installed) |
| `security_report.html` | Generated on CTRL+C with threat summary (MITRE mapped) |
| `state.db` | SQLite persistence for blocked IPs and flow state |
| `app.log` | Structured application logs |

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ --cov=. --cov-report=term-missing
```

## Project Structure

```
gen_ai_sketch_detector/
├── monitor.py              # Main entry point & orchestrator
├── analyzer.py             # AI + ML threat analysis brain
├── dpi_analyzer.py         # Deep packet inspection engine
├── firewall.py             # IP blocking (cross-platform)
├── logger.py               # CSV logging engine (120 columns)
├── data_cleaner.py         # Background data cleaning pipeline
├── dashboard.py            # Flask web dashboard (authenticated)
├── report_generator.py     # Security report generator
├── packet_features.py      # Real packet feature extraction
├── state_manager.py        # SQLite state persistence
├── config.py               # Centralized configuration
├── app_logger.py           # Structured logging system
├── feature_engineering.py  # ML dataset preprocessing
├── generate_dataset.py     # Training data generator (10K+ rows)
├── train_model.py          # Model training with cross-validation
├── random_forest_model.pkl # Pre-trained Random Forest model
├── requirements.txt        # Pinned dependencies
├── Dockerfile              # Container deployment
├── .gitignore              # VCS exclusions
├── templates/
│   └── index.html          # Dashboard frontend (SOC UI)
├── tests/                  # Comprehensive test suite
│   ├── test_analyzer.py
│   ├── test_dpi_analyzer.py
│   ├── test_firewall.py
│   └── ...
└── CSV/                    # ML training datasets
```

## Project Context

Developed by Brijit Maity as a major personal project (2025). The system demonstrates a novel multi-layer AI architecture combining DPI + Random Forest ML + GenAI for stealth network reconnaissance detection, with a 120-column research-grade dataset.

## License

Academic / Research Use
