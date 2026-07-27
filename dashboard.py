"""
dashboard.py — Stealth Reconnaissance SOC Dashboard (Industry-Grade)

Features:
  - Flask + Socket.IO real-time event streaming
  - Basic Authentication & Rate Limiting
  - Content Security Policy (CSP) headers
  - /api/health endpoint for uptime monitoring
  - /api/metrics endpoint for Prometheus scraping
  - Thread-safe event ring buffer using collections.deque
  - Structured logging via app_logger
"""

import os
os.environ["STEALTH_LOG_FILE_NAME"] = "app_dashboard.log"

from flask import Flask, render_template, jsonify, request, Response, send_file, redirect, url_for, make_response
from flask_socketio import SocketIO
from flasgger import Swagger, swag_from
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import threading
import time
import os
import psutil
from collections import deque
import pandas as pd
from pydantic import BaseModel, Field, ValidationError
from typing import Optional

from config import cfg
from state_manager import state
from threat_db import threat_db
from app_logger import get_logger
from auth import auth_manager, requires_jwt
from report_generator import SecurityReporter
import subprocess
log = get_logger(__name__)

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
# Ensure no hardcoded fallback for SECRET_KEY if cfg provides none, but we added a secure fallback in cfg.
app.secret_key = cfg.JWT_SECRET
# Allow CORS from configured origins + wildcard for public access
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Thread-safe ring buffer for UI events
_MAX_EVENTS_IN_MEMORY = cfg.MAX_EVENTS_IN_MEMORY
events = deque(maxlen=_MAX_EVENTS_IN_MEMORY)

# Queue-based emitter to completely decouple simulation from SocketIO
import queue
_emit_queue = queue.Queue(maxsize=500)

def _emitter_worker():
    """Background thread that drains the emit queue and sends to SocketIO."""
    while True:
        try:
            event_type, data = _emit_queue.get(timeout=1)
            try:
                socketio.emit(event_type, data)
            except Exception:
                pass
        except queue.Empty:
            continue
        except Exception:
            continue

_emitter_thread = threading.Thread(target=_emitter_worker, daemon=True)
_emitter_thread.start()

_start_time = time.time()

# ── API Documentation (Swagger) ─────────────────────────────────────
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/api/docs/"
}
swagger = Swagger(app, config=swagger_config)

from werkzeug.exceptions import HTTPException

# ── Global Error Handler ────────────────────────────────────────────
@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return e
    log.error(f"Unhandled Exception: {e}", exc_info=True)
    if request.path.startswith("/api/"):
        return jsonify({"error": "An internal server error occurred."}), 500
    return "An internal server error occurred. Please contact support.", 500


# ── API Rate Limiting (Feature 10) ──────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[cfg.RATE_LIMIT_PUBLIC],
    storage_uri="memory://"
)

# ── Input Validation Schemas ─────────────────────────────────────────
class LoginSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_\.-]+$")
    password: str = Field(..., min_length=6, max_length=128)
    totp_code: Optional[str] = Field(None, min_length=6, max_length=6, pattern=r"^\d{6}$")

# ── Security: JWT Authentication ────────────────────────────────────
@app.route('/api/auth/login', methods=['POST'])
@limiter.limit(cfg.RATE_LIMIT_AUTH)
def login():
    """
    Authenticate and return a JWT.
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: credentials
        schema:
          type: object
          required:
            - username
            - password
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: JWT Token returned
      401:
        description: Invalid credentials
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON payload"}), 400
        
    try:
        validated = LoginSchema(**data)
    except ValidationError as e:
        return jsonify({"error": "Invalid input format"}), 400
        
    role = auth_manager.authenticate(validated.username, validated.password, validated.totp_code)
    if not role:
        return jsonify({"error": "Invalid credentials"}), 401
        
    token = auth_manager.generate_token(data["username"], role)
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "role": role,
        "expires_in": cfg.JWT_EXPIRY_HOURS * 3600
    })

# ── (Custom Rate Limit Removed: Now Using Flask-Limiter) ──────────────

# ── Security: HTTP Headers (CSP & CSRF Defense) ─────────────────────
@app.after_request
def add_security_headers(response):
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.socket.io https://cdn.jsdelivr.net https://d3js.org https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' ws: wss: https://unpkg.com; "
        "worker-src 'self' blob:; "
        "img-src 'self' data: blob: https://unpkg.com;"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # (Removed manual Set-Cookie override to preserve JWT token)
    # Prevent browser caching of the template so UI updates appear immediately
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    
    return response

# ── Routes ──────────────────────────────────────────────────────────
@app.route('/')
def index():
    token = request.cookies.get('jwt_token')
    if not token:
        return redirect(url_for('login_page'))
    
    payload = auth_manager.decode_token(token)
    if "error" in payload:
        return redirect(url_for('login_page'))
        
    current_user = payload.get("sub", "AD")
    return render_template('index.html', current_user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'GET':
        return render_template('register.html')
        
    raw_data = {
        "username": request.form.get('username', ''),
        "password": request.form.get('password', '')
    }
    confirm_password = request.form.get('confirm_password', '')
    if raw_data['password'] != confirm_password:
        return render_template('register.html', error="Passwords do not match.")
    
    try:
        validated = LoginSchema(**raw_data)
    except ValidationError:
        return render_template('register.html', error="Invalid format. Username must be 3-50 chars alphanumeric. Password must be 6+ chars.")
    
    from werkzeug.security import generate_password_hash
    hashed = generate_password_hash(validated.password)
    success = state.create_user(validated.username, hashed, 'analyst')
    if not success:
        return render_template('register.html', error="Operator ID already exists.")
        
    token = auth_manager.generate_token(validated.username, 'analyst')
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('jwt_token', token, httponly=True, max_age=cfg.JWT_EXPIRY_HOURS * 3600)
    return resp

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        return render_template('login.html')
        
    raw_data = {
        "username": request.form.get('username', ''),
        "password": request.form.get('password', ''),
        "totp_code": request.form.get('totp_code') or None
    }
    
    try:
        validated = LoginSchema(**raw_data)
    except ValidationError:
        return render_template('login.html', error="Invalid input format.")
    
    role = auth_manager.authenticate(validated.username, validated.password, validated.totp_code)
    if not role:
        return render_template('login.html', error="Invalid operator ID, clearance code, or 2FA code.")
        
    token = auth_manager.generate_token(validated.username, role)
    
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('jwt_token', token, httponly=True, max_age=cfg.JWT_EXPIRY_HOURS * 3600)
    return resp

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login_page')))
    resp.set_cookie('jwt_token', '', expires=0)
    return resp

@app.route('/api/stats')
@limiter.limit(cfg.RATE_LIMIT_AUTHED)
@requires_jwt()
def get_stats():
    """
    Retrieve global system statistics.
    ---
    tags:
      - Telemetry
    security:
      - Bearer: []
    responses:
      200:
        description: Real-time system stats and threat distributions
    """
    metrics = state.get_all_metrics()
    
    # Build threat distribution for the pie chart
    threat_types = {}
    for event in events:
        if event.get("severity", 0) > 0:
            ttype = event.get("mitre_tactic", "Unknown")
            if not ttype:
                ttype = "Anomalous Traffic"
            threat_types[ttype] = threat_types.get(ttype, 0) + 1

    return jsonify({
        "total_detections": metrics.get('total_scanned', 0),
        "threats_blocked": metrics.get('total_blocked', 0),
        "threat_distribution": threat_types,
        "uptime_seconds": int(time.time() - _start_time)
    })

@app.route('/api/events')
@limiter.limit(cfg.RATE_LIMIT_AUTHED)
@requires_jwt()
def get_recent_events():
    """
    Return recent events for UI initialization.
    ---
    tags:
      - Telemetry
    security:
      - Bearer: []
    responses:
      200:
        description: List of the most recent security events
    """
    return jsonify(list(events))

@app.route('/api/export')
@requires_jwt()
def export_data():
    """
    Export threat events to CSV.
    ---
    tags:
      - Reporting
    security:
      - Bearer: []
    responses:
      200:
        description: CSV file download
    """
    # Use the existing export_csv method from threat_db
    csv_path = threat_db.export_csv()
    if not csv_path or not os.path.exists(csv_path):
        return jsonify({"error": "Failed to generate export"}), 500
        
    return send_file(
        csv_path, 
        mimetype='text/csv', 
        as_attachment=True, 
        download_name=f"cyfocus_threat_report_{time.strftime('%Y%m%d')}.csv"
    )

@app.route('/api/export-pdf')
@requires_jwt()
def export_pdf():
    """
    Export threat events to PDF.
    ---
    tags:
      - Reporting
    security:
      - Bearer: []
    responses:
      200:
        description: PDF file download
    """
    # First ensure we have an up-to-date CSV
    threat_db.export_csv()
    
    reporter = SecurityReporter()
    pdf_path = reporter.generate_pdf_report()
    
    if not pdf_path or not os.path.exists(pdf_path):
        return jsonify({"error": "Failed to generate PDF report"}), 500
        
    return send_file(
        pdf_path, 
        mimetype='application/pdf', 
        as_attachment=True, 
        download_name=f"cyfocus_threat_report_{time.strftime('%Y%m%d')}.pdf"
    )

@app.route('/api/health')
def health_check():
    """
    Unauthenticated health check endpoint for load balancers.
    ---
    tags:
      - System
    responses:
      200:
        description: System health status
    """
    return jsonify({
        "status": "healthy",
        "version": cfg.VERSION,
        "uptime": time.time() - _start_time
    }), 200

@app.route('/api/metrics')
@requires_jwt()
def prometheus_metrics():
    """
    Prometheus-compatible metrics endpoint.
    ---
    tags:
      - System
    security:
      - Bearer: []
    responses:
      200:
        description: Prometheus metrics in text format
    """
    metrics = state.get_all_metrics()
    lines = []
    
    lines.append("# HELP stealth_total_scanned Total number of network events scanned")
    lines.append("# TYPE stealth_total_scanned counter")
    lines.append(f"stealth_total_scanned {metrics.get('total_scanned', 0)}")
    
    lines.append("# HELP stealth_total_blocked Total number of threats blocked")
    lines.append("# TYPE stealth_total_blocked counter")
    lines.append(f"stealth_total_blocked {metrics.get('total_blocked', 0)}")
    
    lines.append("# HELP stealth_active_blocks Currently active firewall blocks")
    lines.append("# TYPE stealth_active_blocks gauge")
    lines.append(f"stealth_active_blocks {state.get_blocked_ip_count()}")
    
    lines.append("# HELP stealth_uptime_seconds Process uptime in seconds")
    lines.append("# TYPE stealth_uptime_seconds counter")
    lines.append(f"stealth_uptime_seconds {time.time() - _start_time}")
    
    try:
        lines.append("# HELP stealth_cpu_percent CPU usage percentage")
        lines.append("# TYPE stealth_cpu_percent gauge")
        lines.append(f"stealth_cpu_percent {psutil.cpu_percent()}")
        
        lines.append("# HELP stealth_memory_percent Memory usage percentage")
        lines.append("# TYPE stealth_memory_percent gauge")
        lines.append(f"stealth_memory_percent {psutil.virtual_memory().percent}")
    except Exception:
        pass
        
    return Response("\n".join(lines) + "\n", mimetype="text/plain")

# ── Threat Database API Endpoints (Feature 4) ──────────────────────
@app.route('/api/threats')
@requires_jwt()
def get_threats():
    """
    Query threats from the database with optional filters.
    ---
    tags:
      - Threat Intelligence
    security:
      - Bearer: []
    parameters:
      - in: query
        name: start_time
        type: string
        description: Start time filter
      - in: query
        name: limit
        type: integer
        default: 100
        description: Max rows to return
    responses:
      200:
        description: A list of threat events
    """
    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')
    source_ip = request.args.get('source_ip')
    severity_min = request.args.get('severity_min', type=float)
    detection_method = request.args.get('detection_method')
    limit = request.args.get('limit', 100, type=int)
    limit = min(limit, 1000)  # Cap at 1000

    results = threat_db.query_threats(
        start_time=start_time,
        end_time=end_time,
        source_ip=source_ip,
        severity_min=severity_min,
        detection_method=detection_method,
        limit=limit
    )
    return jsonify({"count": len(results), "threats": results})

@app.route('/api/threats/history')
@requires_jwt()
def get_threats_history():
    """
    Get threats from X minutes ago for Time Machine mode.
    """
    minutes_ago = request.args.get('minutes_ago', 5, type=int)
    
    # Calculate timestamp for 'minutes_ago'
    import datetime
    target_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=minutes_ago)
    start_time = (target_time - datetime.timedelta(minutes=1)).isoformat() + 'Z'
    end_time = (target_time + datetime.timedelta(minutes=1)).isoformat() + 'Z'
    
    results = threat_db.query_threats(
        start_time=start_time,
        end_time=end_time,
        limit=100
    )
    
    # Map to the format UI expects for events
    events = []
    for r in results:
        events.append({
            "id": r['id'],
            "timestamp": r['timestamp'],
            "source_ip": r['source_ip'],
            "dest_ip": r['dest_ip'],
            "dest_port": r['dest_port'],
            "threat_type": r['threat_type'],
            "severity": r['severity']
        })
        
    return jsonify({"events": events})

@app.route('/api/ip-reputation')
@requires_jwt()
def get_ip_reputation():
    """
    Get IP reputation data.
    ---
    tags:
      - Threat Intelligence
    security:
      - Bearer: []
    parameters:
      - in: query
        name: ip
        type: string
        description: Target IP Address
      - in: query
        name: limit
        type: integer
        default: 50
    responses:
      200:
        description: IP reputation details
    """
    ip = request.args.get('ip')
    limit = request.args.get('limit', 50, type=int)
    results = threat_db.get_ip_reputation(ip_address=ip, limit=limit)
    return jsonify({"count": len(results), "reputation": results})

@app.route('/api/threat-stats')
@requires_jwt()
def get_threat_stats():
    """
    Get aggregated threat statistics.
    ---
    tags:
      - Threat Intelligence
    security:
      - Bearer: []
    responses:
      200:
        description: Threat stats mapping
    """
    stats = threat_db.get_threat_stats()
    return jsonify(stats)

@app.route('/api/firewall-stats')
@requires_jwt()
def get_firewall_stats():
    """
    Get detailed firewall block statistics.
    ---
    tags:
      - Telemetry
    security:
      - Bearer: []
    responses:
      200:
        description: Status of the firewall
    """
    # Import firewall lazily to avoid circular imports
    try:
        from firewall import Firewall
        # Note: This accesses a module-level instance — works if monitor creates it
        return jsonify({"message": "Firewall stats available via /api/metrics"})
    except Exception:
        return jsonify({"error": "Firewall stats not available"}), 503

@app.route('/api/export')
@requires_jwt(['admin'])
def export_excel():
    """
    Download the main detection log Excel file.
    ---
    tags:
      - Export
    security:
      - Bearer: []
    responses:
      200:
        description: Excel file download
      404:
        description: Log file not found
    """
    import pandas as pd
    import io
    csv_path = os.path.join(cfg.BASE_DIR, cfg.LOG_CSV)
    if os.path.exists(csv_path):
        try:
            df = pd.read_csv(csv_path)
            output = io.BytesIO()
            df.to_excel(output, index=False, engine='openpyxl')
            output.seek(0)
            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=f'stealth_detection_logs_{time.strftime("%Y%m%d_%H%M%S")}.xlsx'
            )
        except Exception as e:
            return jsonify({"error": f"Failed to generate Excel: {e}"}), 500
    return jsonify({"error": "Log file not found"}), 404

@app.route('/api/forensics/pcap')
@requires_jwt(['admin'])
def view_pcap():
    """
    Generate a hex dump from a saved PCAP file.
    ---
    tags:
      - Forensics
    security:
      - Bearer: []
    parameters:
      - in: query
        name: file
        type: string
        description: Relative path to the PCAP file
    responses:
      200:
        description: Hex dump of the PCAP
    """
    file_path = request.args.get('file')
    if not file_path or '..' in file_path or not file_path.startswith('pcap_archive'):
        return jsonify({"error": "Invalid file path"}), 400
        
    full_path = os.path.join(cfg.BASE_DIR, file_path)
    if not os.path.exists(full_path):
        return jsonify({"error": "PCAP file not found"}), 404
        
    try:
        from scapy.all import rdpcap, hexdump
        import io
        import sys
        
        packets = rdpcap(full_path)
        if not packets:
            return jsonify({"hex": "Empty PCAP"})
            
        # Capture hexdump output
        old_stdout = sys.stdout
        sys.stdout = capture = io.StringIO()
        hexdump(packets[0])
        sys.stdout = old_stdout
        
        hex_data = capture.getvalue()
        return jsonify({"hex": hex_data, "packet_count": len(packets)})
    except Exception as e:
        log.error(f"Failed to read PCAP: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/export-events')
@requires_jwt(['admin'])
def export_events_excel():
    """
    Download current in-memory dashboard events as Excel.
    ---
    tags:
      - Export
    security:
      - Bearer: []
    responses:
      200:
        description: Excel file of current events
    """
    import pandas as pd
    import io
    
    if events:
        try:
            df = pd.DataFrame(list(events))
            output = io.BytesIO()
            df.to_excel(output, index=False, engine='openpyxl')
            output.seek(0)
            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=f'dashboard_events_{time.strftime("%Y%m%d_%H%M%S")}.xlsx'
            )
        except Exception as e:
            return jsonify({"error": f"Failed to generate Excel: {e}"}), 500
            
    # Fallback for no events
    output = io.BytesIO()
    pd.DataFrame([{"Message": "No events captured yet"}]).to_excel(output, index=False, engine='openpyxl')
    output.seek(0)
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'dashboard_events_empty_{time.strftime("%Y%m%d_%H%M%S")}.xlsx'
    )

@app.route('/api/signatures/add', methods=['POST'])
@requires_jwt(['admin'])
def add_signature():
    """Add a custom DPI signature."""
    try:
        data = request.get_json()
        name = data.get('name')
        pattern = data.get('pattern')
        severity = data.get('severity', 'High')
        cwe = data.get('category', 'Custom')
        
        if not name or not pattern:
            return jsonify({"success": False, "error": "Missing name or pattern"}), 400
            
        import json, os
        custom_sig_path = 'custom_signatures.json'
        custom_sigs = []
        if os.path.exists(custom_sig_path):
            with open(custom_sig_path, 'r') as f:
                custom_sigs = json.load(f)
                
        new_sig = {
            "id": f"DPI-CUST-{len(custom_sigs)+1:03d}",
            "name": name,
            "pattern": pattern,
            "severity": severity,
            "cwe": cwe
        }
        custom_sigs.append(new_sig)
        
        with open(custom_sig_path, 'w') as f:
            json.dump(custom_sigs, f, indent=4)
            
        return jsonify({"success": True})
    except Exception as e:
        log.error(f"Failed to add signature: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/signatures')
@requires_jwt()
def get_signatures():
    """
    Get the list of active DPI signatures.
    ---
    tags:
      - Threat Intelligence
    security:
      - Bearer: []
    responses:
      200:
        description: List of signatures
    """
    try:
        from dpi_analyzer import DPIAnalyzer
        dpi = DPIAnalyzer(None)
        return jsonify({"signatures": dpi.get_signatures()})
    except Exception as e:
        log.error(f"Failed to fetch signatures: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/soar/run', methods=['POST'])
@requires_jwt(['admin'])
def run_soar():
    """
    Execute a SOAR playbook (e.g. Nmap profile).
    ---
    tags:
      - SOAR
    security:
      - Bearer: []
    parameters:
      - in: body
        name: params
        schema:
          type: object
          properties:
            ip:
              type: string
    responses:
      200:
        description: Output of the SOAR playbook
    """
    data = request.get_json()
    target_ip = data.get('ip')
    if not target_ip:
        return jsonify({"error": "IP address required"}), 400
        
    try:
        from soar_engine import soar_engine
        output = soar_engine.execute_nmap_scan(target_ip)
        return jsonify({"status": "success", "output": output})
    except Exception as e:
        log.error(f"SOAR error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/generate-rule', methods=['POST'])
@requires_jwt(['admin'])
def generate_rule():
    """
    Generate Snort/Suricata rules for a given threat IP.
    ---
    tags:
      - Threat Intelligence
    security:
      - Bearer: []
    parameters:
      - in: body
        name: params
        schema:
          type: object
          properties:
            ip:
              type: string
    responses:
      200:
        description: Generated Suricata rule
    """
    data = request.get_json()
    target_ip = data.get('ip')
    if not target_ip:
        return jsonify({"error": "IP address required"}), 400
        
    results = threat_db.query_threats(source_ip=target_ip, limit=1)
    if not results:
        # Fallback if not in DB
        msg = f"Suspicious Activity from {target_ip}"
        tech = "T1190"
        port = "any"
    else:
        threat = results[0]
        msg = threat.get("threat_intel", "Malicious activity detected").replace('"', "'")
        tech = threat.get("mitre_technique_id", "T1190")
        port = threat.get("destination_port", "any")
        if not port or port == 0:
            port = "any"
            
    # Remove newlines and weird chars from msg
    msg = "".join(c for c in msg if c.isprintable())[:100]
    
    rule = f'drop tcp {target_ip} any -> $HOME_NET {port} (msg:"{msg}"; flags:S; reference:url,mitre.org/techniques/{tech}; classtype:attempted-recon; sid:1000001; rev:1;)'
    
    return jsonify({"status": "success", "rule": rule, "format": "suricata"})

# ── Data Push Interfaces ────────────────────────────────────────────
def _resolve_and_emit_geoip(event_data):
    """Background thread to resolve GeoIP without blocking the broadcast API."""
    source_ip = event_data.get("source_ip") or event_data.get("source")
    if source_ip:
        try:
            from geoip import geoip_resolver
            geo_data = geoip_resolver.resolve(source_ip)
            event_data['lat'] = geo_data['lat']
            event_data['lon'] = geo_data['lon']
            event_data['city'] = geo_data['city']
            try:
                _emit_queue.put_nowait(('geoip_update', {'id': event_data.get('id'), 'geo': geo_data}))
            except queue.Full:
                pass
        except Exception as e:
            log.error(f"GeoIP thread error: {e}")

def push_event_to_ui(event_data):
    """Push an event to the web UI and store in local ring buffer."""
    events.appendleft(event_data)
    try:
        _emit_queue.put_nowait(('new_event', event_data))
        
        # Simulated Automated Alert for Critical threats
        if event_data.get('severity') == 'Critical':
            alert_msg = f"Automated Webhook/Email sent to sec-ops@cyfocus.com for {event_data.get('threat_type')} from {event_data.get('source_ip')}"
            _emit_queue.put_nowait(('terminal_alert', {'message': alert_msg}))
            log.warning(alert_msg)
            
    except queue.Full:
        pass  # Drop event if queue is full
        
    threading.Thread(target=_resolve_and_emit_geoip, args=(event_data,), daemon=True).start()

def push_enrichment_to_ui(event_id, enrichment_text):
    """Update an existing event with LLM enrichment details."""
    for event in events:
        if event.get("id") == event_id:
            event["enrichment"] = enrichment_text
            break
    try:
        _emit_queue.put_nowait(('enrichment_ready', {"id": event_id, "enrichment": enrichment_text}))
    except queue.Full:
        pass

@app.route('/api/internal/broadcast', methods=['POST'])
@limiter.exempt
def internal_broadcast():
    """Internal endpoint for monitor.py to send events to dashboard."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data"}), 400
        
    action = data.get("action")
    if action == "new_event":
        push_event_to_ui(data.get("event"))
    elif action == "enrichment":
        push_enrichment_to_ui(data.get("event_id"), data.get("enrichment"))
        
    return jsonify({"status": "ok"}), 200

@app.route('/api/terminal/run', methods=['POST'])
@requires_jwt(['admin', 'analyst'])
def run_terminal_command():
    data = request.get_json()
    cmd_str = data.get('command', '').strip()
    if not cmd_str:
        return jsonify({"error": "Empty command"})
        
    parts = cmd_str.split()
    base_cmd = parts[0].lower()
    
    if base_cmd == 'help':
        help_text = (
            "CyFocus SOC Terminal Commands:\n"
            "  help      - Show this message\n"
            "  whois     - Get real IP/ISP info (ip-api.com)\n"
            "  nslookup  - Resolve domain to IP\n"
            "  ping      - Fast ICMP echo request\n"
            "  block     - Simulate Edge Router IP block\n"
            "  date      - Print server time\n"
            "  whoami    - Print current user\n"
            "  uptime    - Print server uptime\n"
            "  clear     - Clear terminal buffer"
        )
        return jsonify({"result": help_text})
    
    elif base_cmd == 'whois':
        if len(parts) < 2:
            return jsonify({"error": "Usage: whois <ip>"})
        import requests
        try:
            r = requests.get(f"http://ip-api.com/json/{parts[1]}", timeout=2)
            res = r.json()
            if res.get("status") == "success":
                out = (
                    f"WHOIS Record for {parts[1]}:\n"
                    f"ISP / Org:   {res.get('isp')} / {res.get('org')}\n"
                    f"Location:    {res.get('city')}, {res.get('country')}\n"
                    f"AS Number:   {res.get('as')}\n"
                )
                return jsonify({"result": out})
            else:
                return jsonify({"error": f"Lookup failed: {res.get('message')}"})
        except Exception as e:
            return jsonify({"error": f"API Error: {str(e)}"})
            
    elif base_cmd == 'nslookup':
        if len(parts) < 2:
            return jsonify({"error": "Usage: nslookup <domain>"})
        import socket
        try:
            ip = socket.gethostbyname(parts[1])
            return jsonify({"result": f"Server:  CyFocus Internal DNS\n\nName:    {parts[1]}\nAddress: {ip}"})
        except Exception as e:
            return jsonify({"error": f"DNS resolution failed: {str(e)}"})
        
    elif base_cmd == 'ping':
        if len(parts) < 2:
            return jsonify({"error": "Usage: ping <ip>"})
        import subprocess
        try:
            # Fast ping: 1 packet, 500ms timeout
            output = subprocess.check_output(['ping', '-n', '1', '-w', '500', parts[1]], stderr=subprocess.STDOUT, text=True)
            return jsonify({"result": output})
        except subprocess.CalledProcessError as e:
            return jsonify({"error": e.output})
        except Exception as e:
            return jsonify({"error": str(e)})
            
    elif base_cmd == 'block':
        if len(parts) < 2:
            return jsonify({"error": "Usage: block <ip>"})
        ip = parts[1]
        try:
            with open("blocked_ips.txt", "a") as f:
                import datetime
                f.write(f"{datetime.datetime.now().isoformat()} - {ip}\n")
            out = (
                f"[OK] Edge Router Command Executed.\n"
                f"Rule 1042: DROP ALL from {ip} to ANY\n"
                f"Status: Committed to running-config."
            )
            return jsonify({"result": out})
        except Exception as e:
            return jsonify({"error": f"Failed to apply block: {str(e)}"})
            
    elif base_cmd == 'date':
        import datetime
        return jsonify({"result": datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")})
        
    elif base_cmd == 'whoami':
        import os
        return jsonify({"result": os.environ.get('USERNAME', 'root')})
        
    elif base_cmd == 'uptime':
        import time
        import psutil
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        return jsonify({"result": f"up {hours} hours, {minutes} minutes, load average: 0.05, 0.02, 0.01"})
        
    else:
        return jsonify({"error": f"Command not found: {base_cmd}"})


@app.route('/api/chat', methods=['POST'])
@requires_jwt(['admin', 'analyst', 'viewer'])
def ai_chat():
    data = request.get_json()
    msg = data.get('message', '').lower()
    
    try:
        import google.generativeai as genai
        import json
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            # Simulated response for demo purposes
            reply = "This is a simulated AI response (GEMINI_API_KEY is missing). Based on recent telemetry, multiple automated scans and brute-force attempts have been detected. Ensure your firewall rules are updated and strict rate limiting is applied to public endpoints."
            return jsonify({"reply": reply})
            
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        # Grab up to the last 10 events from the ring buffer
        recent_events = list(events)[:10]
        # Clean up events to save tokens (remove huge raw payloads if any, though they're mostly small)
        clean_events = []
        for e in recent_events:
            clean_events.append({
                "src_ip": e.get("source_ip"),
                "dst_ip": e.get("destination_ip"),
                "method": e.get("method"),
                "severity": e.get("severity"),
                "mitre": e.get("mitre_technique")
            })
            
        telemetry = json.dumps(clean_events, indent=2) if clean_events else "No active threats."
        
        prompt = (
            "You are an elite CyFocus AI Cyber Assistant SOC Analyst. "
            "You provide actionable, hyper-specific mitigation strategies based on live telemetry. "
            f"Here are the latest threats currently attacking the network:\n{telemetry}\n\n"
            f"The user asks: '{msg}'\n\n"
            "Respond professionally, concisely (1-3 sentences max), and directly reference the active threat IPs or MITRE techniques if relevant."
        )
        
        response = model.generate_content(prompt)
        reply = response.text.strip()
    except Exception as e:
        log.error(f"GenAI Chat Error: {e}")
        reply = f"System operating in restricted mode. Error connecting to AI: {e}. Please review the telemetry feed manually."
        
    return jsonify({"reply": reply})

def _generate_self_signed_cert(cert_path, key_path):
    cert_dir = os.path.dirname(cert_path)
    if cert_dir:
        os.makedirs(cert_dir, exist_ok=True)
    log.info("Generating self-signed SSL certificate for Dashboard...")
    try:
        # Requires openssl in PATH
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:4096", "-nodes",
            "-out", cert_path, "-keyout", key_path, "-days", "365",
            "-subj", "/CN=StealthSOC"
        ], check=True, capture_output=True)
        log.info(f"Certificate generated at {cert_path}")
    except Exception as e:
        log.error(f"Failed to generate self-signed cert: {e}. Falling back to HTTP.")

def run_dashboard():
    """Start the Flask + SocketIO server."""
    ssl_args = {}
    if getattr(cfg, 'ENABLE_TLS', False):
        if not os.path.exists(cfg.TLS_CERT_PATH) or not os.path.exists(cfg.TLS_KEY_PATH):
            _generate_self_signed_cert(cfg.TLS_CERT_PATH, cfg.TLS_KEY_PATH)
            
        if os.path.exists(cfg.TLS_CERT_PATH) and os.path.exists(cfg.TLS_KEY_PATH):
            log.info("TLS Enabled. Using HTTPS.")
            ssl_args['ssl_context'] = (cfg.TLS_CERT_PATH, cfg.TLS_KEY_PATH)
        else:
            log.warning("TLS was enabled but certs are missing. Falling back to HTTP.")

    log.info(f"Starting dashboard server on 0.0.0.0:{cfg.DASHBOARD_PORT} (localhost + public)")
    import logging
    logging.getLogger('werkzeug').disabled = True
    
    # Run with SocketIO (eventlet/gevent if available, otherwise threading)
    socketio.run(
        app, 
        host='0.0.0.0',  # Bind to all interfaces: localhost + public network
        port=cfg.DASHBOARD_PORT, 
        debug=False, 
        use_reloader=False,
        allow_unsafe_werkzeug=True,  # For dev/testing
        **ssl_args
    )

if __name__ == "__main__":
    threading.Thread(target=run_dashboard, daemon=True).start()
    while True:
        time.sleep(1)
