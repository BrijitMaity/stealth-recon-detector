"""
report_generator.py — Security Report Generation (Industry-Grade)

Features:
  - Memory-efficient processing of large CSV logs using pandas chunking.
  - MITRE ATT&CK and CWE framework mapping.
  - HTML format report generation with inline CSS for SOC distribution.
  - Structured logging.
"""

import pandas as pd
import datetime
import os
import html
import json
from fpdf import FPDF
from app_logger import get_logger
from config import cfg

log = get_logger(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AI Stealth Recon SOC - Executive Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #2980b9; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; color: #333; font-weight: 600; }}
        .threat-row {{ background-color: #fff5f5; }}
        .summary-box {{ display: flex; gap: 20px; margin-top: 20px; }}
        .stat-card {{ background: #34495e; color: #fff; padding: 20px; border-radius: 8px; flex: 1; text-align: center; }}
        .stat-card.alert {{ background: #e74c3c; }}
        .stat-value {{ font-size: 2em; font-weight: bold; margin-top: 10px; }}
        .footer {{ margin-top: 40px; text-align: center; font-size: 0.9em; color: #7f8c8d; }}
        .charts-row {{ display: flex; flex-wrap: wrap; gap: 20px; margin-top: 30px; justify-content: space-between; }}
        .chart-container {{ background: #f8f9fa; border: 1px solid #ddd; border-radius: 8px; padding: 20px; flex: 1 1 calc(50% - 20px); box-sizing: border-box; min-width: 300px; }}
        .chart-container.full-width {{ flex: 1 1 100%; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Stealth Reconnaissance Detection Report</h1>
        <p><strong>Generated on:</strong> {date_generated}</p>
        
        <div class="summary-box">
            <div class="stat-card">
                <div>Total Traffic Events</div>
                <div class="stat-value">{total_events}</div>
            </div>
            <div class="stat-card alert">
                <div>Confirmed Threats</div>
                <div class="stat-value">{threat_count}</div>
            </div>
        </div>

        <h2>Global Threat Origin Map</h2>
        <div class="charts-row">
            <div class="chart-container full-width">
                <div id="map" style="height: 400px; width: 100%; border-radius: 8px;"></div>
            </div>
        </div>

        <h2>Threat Distribution Analytics</h2>
        <div class="charts-row">
            <div class="chart-container full-width">
                <canvas id="temporalChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="protocolChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="tacticsChart"></canvas>
            </div>
        </div>

        <div class="charts-row">
            <div class="chart-container">
                <h2>Top Attackers (by IP)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Source IP</th>
                            <th>Threat Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {attackers_rows}
                    </tbody>
                </table>
            </div>
            <div class="chart-container">
                <h2>MITRE ATT&CK Tactics Detected</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Tactic</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {tactics_rows}
                    </tbody>
                </table>
            </div>
        </div>

        <h2>Recent Critical Threats (Last 20)</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Method</th>
                    <th>MITRE Tactic</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>
                {recent_threats_rows}
            </tbody>
        </table>

        <div class="footer">
            Generated by AI Stealth Recon SOC Engine v{version}<br>
            Security Status: SECURED
        </div>
    </div>

    <script>
        const temporalData = {temporal_json};
        const protocolData = {protocol_json};
        const tacticsData = {tactics_json};
        const mapData = {map_json};

        // Initialize Map
        const map = L.map('map').setView([20.0, 0.0], 2);
        L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
            attribution: '&copy; OpenStreetMap contributors &copy; CARTO'
        }}).addTo(map);

        mapData.forEach(item => {{
            if(item.lat && item.lon) {{
                L.circleMarker([item.lat, item.lon], {{
                    color: '#e74c3c',
                    fillColor: '#e74c3c',
                    fillOpacity: 0.6,
                    radius: Math.min(item.count * 2 + 3, 15)
                }}).addTo(map).bindPopup(`<b>${{item.city}}, ${{item.country}}</b><br>Threats: ${{item.count}}`);
            }}
        }});

        // Temporal Chart
        new Chart(document.getElementById('temporalChart'), {{
            type: 'line',
            data: {{
                labels: temporalData.labels,
                datasets: [{{
                    label: 'Threat Events over Time',
                    data: temporalData.data,
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.2)',
                    fill: true,
                    tension: 0.4
                }}]
            }},
            options: {{ responsive: true, plugins: {{ title: {{ display: true, text: 'Threat Activity Timeline' }} }} }}
        }});

        // Protocol/Port Chart
        new Chart(document.getElementById('protocolChart'), {{
            type: 'doughnut',
            data: {{
                labels: protocolData.labels,
                datasets: [{{
                    data: protocolData.data,
                    backgroundColor: ['#3498db', '#e74c3c', '#f1c40f', '#2ecc71', '#9b59b6', '#34495e']
                }}]
            }},
            options: {{ responsive: true, plugins: {{ title: {{ display: true, text: 'Top Targeted Ports' }} }} }}
        }});

        // Tactics Chart
        new Chart(document.getElementById('tacticsChart'), {{
            type: 'bar',
            data: {{
                labels: tacticsData.labels,
                datasets: [{{
                    label: 'MITRE Tactics',
                    data: tacticsData.data,
                    backgroundColor: '#3498db'
                }}]
            }},
            options: {{ responsive: true, plugins: {{ title: {{ display: true, text: 'MITRE Tactics Distribution' }} }} }}
        }});
    </script>
</body>
</html>
"""

class SecurityReporter:
    def __init__(self, log_file=None):
        self.log_file = log_file or cfg.LOG_CSV

    def generate_report(self, output_file="security_report.html"):
        """Generates a summary HTML report from the CSV logs."""
        if not os.path.exists(self.log_file):
            log.warning("No log file found to generate report.")
            return None
        
        try:
            log.info(f"Generating report from {self.log_file}...")
            
            # Read large CSVs in chunks to avoid OOM
            if os.path.getsize(self.log_file) > 50_000_000:  # >50MB
                chunk_list = []
                for chunk in pd.read_csv(self.log_file, chunksize=50_000, on_bad_lines='skip', low_memory=False):
                    chunk_list.append(chunk)
                df = pd.concat(chunk_list, ignore_index=True)
            else:
                df = pd.read_csv(self.log_file, on_bad_lines='skip', low_memory=False)
                
            if df.empty:
                log.info("Log file is empty.")
                return None

            total_events = len(df)

            # Compatibility: support old and new schemas
            method_col  = 'Method' if 'Method' in df.columns else ('Detection_Method' if 'Detection_Method' in df.columns else None)
            source_col  = 'Source' if 'Source' in df.columns else ('Source_IP' if 'Source_IP' in df.columns else None)
            conf_col    = 'Confidence' if 'Confidence' in df.columns else ('AI Confidence' if 'AI Confidence' in df.columns else None)
            tactic_col  = 'MITRE_Tactic' if 'MITRE_Tactic' in df.columns else None

            if method_col:
                threats = df[df[method_col].str.contains('GenAI|DPI', na=False, case=False)]
            else:
                threats = pd.DataFrame()

            threat_count = len(threats)

            # Attackers Rows
            attackers_rows = ""
            if source_col and not threats.empty:
                attackers = threats[source_col].value_counts().head(10)
                for ip, count in attackers.items():
                    attackers_rows += f"<tr><td>{html.escape(str(ip))}</td><td>{count}</td></tr>"
            else:
                attackers_rows = "<tr><td colspan='2'>No attackers identified</td></tr>"

            # Tactics Rows
            tactics_rows = ""
            if tactic_col and not threats.empty:
                tactics = threats[tactic_col].value_counts()
                for tactic, count in tactics.items():
                    tactic_disp = "Unknown" if pd.isna(tactic) or not str(tactic).strip() else str(tactic)
                    tactics_rows += f"<tr><td>{html.escape(tactic_disp)}</td><td>{count}</td></tr>"
            else:
                tactics_rows = "<tr><td colspan='2'>MITRE ATT&CK mapping not available in logs</td></tr>"

            # Recent Threats Rows
            recent_threats_rows = ""
            if not threats.empty:
                for _, row in threats.tail(20).iterrows():
                    ts = html.escape(str(row.get('Timestamp', 'N/A')))
                    src = html.escape(str(row.get(source_col, 'N/A')))
                    meth = html.escape(str(row.get(method_col, 'N/A')))
                    tac = html.escape(str(row.get(tactic_col, 'N/A'))) if tactic_col else 'N/A'
                    conf = html.escape(str(row.get(conf_col, 'N/A')))
                    recent_threats_rows += f"<tr class='threat-row'><td>{ts}</td><td>{src}</td><td>{meth}</td><td>{tac}</td><td>{conf}</td></tr>"
            else:
                recent_threats_rows = "<tr><td colspan='5'>No critical threats detected.</td></tr>"

            # Temporal Data (group by Minute)
            temporal_json = {"labels": [], "data": []}
            if not threats.empty and 'Timestamp' in threats.columns:
                try:
                    threats_copy = threats.copy()
                    threats_copy['Time'] = pd.to_datetime(threats_copy['Timestamp']).dt.strftime('%H:%M')
                    temporal_counts = threats_copy['Time'].value_counts().sort_index()
                    temporal_json = {"labels": temporal_counts.index.tolist(), "data": temporal_counts.values.tolist()}
                except Exception as e:
                    log.warning(f"Failed to parse temporal data: {e}")

            # Protocol/Port Data
            protocol_json = {"labels": [], "data": []}
            if not df.empty and 'Destination_Port' in df.columns:
                try:
                    port_counts = df['Destination_Port'].value_counts().head(6)
                    protocol_json = {"labels": [f"Port {int(p)}" for p in port_counts.index], "data": port_counts.values.tolist()}
                except Exception as e:
                    log.warning(f"Failed to parse protocol data: {e}")

            # Tactics JSON for chart
            tactics_json = {"labels": [], "data": []}
            if tactic_col and not threats.empty:
                try:
                    tactics = threats[tactic_col].value_counts().head(6)
                    tactics_json = {"labels": [str(t) for t in tactics.index], "data": tactics.values.tolist()}
                except Exception as e:
                    log.warning(f"Failed to parse tactics json: {e}")

            # Map JSON
            geo_data = []
            map_json = "[]"
            if not threats.empty and 'Geo_Lat' in threats.columns and 'Geo_Lon' in threats.columns:
                try:
                    geo_counts = threats.groupby(['Geo_Country', 'Geo_City', 'Geo_Lat', 'Geo_Lon']).size().reset_index(name='count')
                    for _, row in geo_counts.iterrows():
                        if pd.notna(row['Geo_Lat']) and pd.notna(row['Geo_Lon']):
                            geo_data.append({
                                "country": str(row.get('Geo_Country', 'Unknown')),
                                "city": str(row.get('Geo_City', 'Unknown')),
                                "lat": float(row['Geo_Lat']),
                                "lon": float(row['Geo_Lon']),
                                "count": int(row['count'])
                            })
                    map_json = json.dumps(geo_data)
                except Exception as e:
                    log.warning(f"Failed to parse geo data: {e}")

            # Render HTML
            html_content = HTML_TEMPLATE.format(
                date_generated=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                total_events=f"{total_events:,}",
                threat_count=f"{threat_count:,}",
                attackers_rows=attackers_rows,
                tactics_rows=tactics_rows,
                recent_threats_rows=recent_threats_rows,
                version=cfg.VERSION,
                temporal_json=json.dumps(temporal_json),
                protocol_json=json.dumps(protocol_json),
                tactics_json=json.dumps(tactics_json),
                map_json=map_json
            )

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            log.info(f"Report generated successfully: {output_file}")
            return output_file
            
        except Exception as e:
            log.error(f"Failed to generate HTML report: {e}")
            return None

    def generate_pdf_report(self, output_file="security_report.pdf"):
        """Generates a PDF report from the CSV logs using fpdf2."""
        if not os.path.exists(self.log_file):
            log.warning("No log file found to generate PDF report.")
            return None
        
        try:
            log.info(f"Generating PDF report from {self.log_file}...")
            if os.path.getsize(self.log_file) > 50_000_000:
                chunk_list = []
                for chunk in pd.read_csv(self.log_file, chunksize=50_000, on_bad_lines='skip', low_memory=False):
                    chunk_list.append(chunk)
                df = pd.concat(chunk_list, ignore_index=True)
            else:
                df = pd.read_csv(self.log_file, on_bad_lines='skip', low_memory=False)
                
            if df.empty:
                log.info("Log file is empty.")
                return None

            total_events = len(df)
            method_col = 'Method' if 'Method' in df.columns else ('Detection_Method' if 'Detection_Method' in df.columns else None)
            source_col = 'Source' if 'Source' in df.columns else ('Source_IP' if 'Source_IP' in df.columns else None)
            conf_col = 'Confidence' if 'Confidence' in df.columns else ('AI Confidence' if 'AI Confidence' in df.columns else None)
            
            if method_col:
                threats = df[df[method_col].str.contains('GenAI|DPI', na=False, case=False)]
            else:
                threats = pd.DataFrame()
            threat_count = len(threats)

            pdf = FPDF()
            pdf.add_page()
            
            # Title
            pdf.set_font('helvetica', 'B', 16)
            pdf.cell(0, 10, 'Stealth Reconnaissance Detection Report', ln=1, align='C')
            pdf.set_font('helvetica', '', 10)
            pdf.cell(0, 10, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1, align='C')
            pdf.ln(10)
            
            # Summary
            pdf.set_font('helvetica', 'B', 12)
            pdf.cell(0, 10, 'Executive Summary', ln=1)
            pdf.set_font('helvetica', '', 11)
            pdf.cell(0, 10, f"Total Traffic Events: {total_events:,}", ln=1)
            pdf.cell(0, 10, f"Confirmed Threats: {threat_count:,}", ln=1)
            pdf.ln(5)
            
            # Top Attackers
            pdf.set_font('helvetica', 'B', 12)
            pdf.cell(0, 10, 'Top Attackers (by IP)', ln=1)
            pdf.set_font('helvetica', '', 10)
            
            if source_col and not threats.empty:
                attackers = threats[source_col].value_counts().head(5)
                for ip, count in attackers.items():
                    pdf.cell(0, 8, f"- {ip}: {count} threats", ln=1)
            else:
                pdf.cell(0, 8, "No attackers identified.", ln=1)
            pdf.ln(5)
            
            # Recent Critical Threats
            pdf.set_font('helvetica', 'B', 12)
            pdf.cell(0, 10, 'Recent Critical Threats (Last 10)', ln=1)
            pdf.set_font('helvetica', '', 9)
            
            # Table Header
            col_widths = [40, 35, 95, 20]
            headers = ['Timestamp', 'Source IP', 'Method', 'Conf']
            for i, h in enumerate(headers):
                pdf.cell(col_widths[i], 8, h, border=1)
            pdf.ln()
            
            if not threats.empty:
                for _, row in threats.tail(10).iterrows():
                    ts = str(row.get('Timestamp', 'N/A'))[:19]
                    src = str(row.get(source_col, 'N/A'))
                    meth = str(row.get(method_col, 'N/A'))[:50]  # truncate long methods
                    conf = str(row.get(conf_col, 'N/A'))
                    pdf.cell(col_widths[0], 8, ts, border=1)
                    pdf.cell(col_widths[1], 8, src, border=1)
                    pdf.cell(col_widths[2], 8, meth, border=1)
                    pdf.cell(col_widths[3], 8, conf, border=1)
                    pdf.ln()
            else:
                pdf.cell(sum(col_widths), 8, "No critical threats detected.", border=1, ln=1, align='C')
            
            pdf.ln(10)
            pdf.set_font('helvetica', 'I', 8)
            pdf.cell(0, 10, f"Generated by AI Stealth Recon SOC Engine v{cfg.VERSION} - Security Status: SECURED", ln=1, align='C')
            
            pdf.output(output_file)
            log.info(f"PDF Report generated successfully: {output_file}")
            return output_file
            
        except Exception as e:
            log.error(f"Failed to generate PDF report: {e}")
            return None

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate SOC HTML Security Report")
    parser.add_argument("--log-file", type=str, default=cfg.LOG_CSV, help="Path to the log file")
    parser.add_argument("--output-file", type=str, default="security_report.html", help="Path to the output report HTML file")
    args = parser.parse_args()
    
    reporter = SecurityReporter(log_file=args.log_file)
    reporter.generate_report(output_file=args.output_file)
