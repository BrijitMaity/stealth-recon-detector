import socket
import threading
import time
from app_logger import get_logger
from threat_db import threat_db

log = get_logger(__name__)

class Honeypot:
    def __init__(self, ports=(22, 21, 8080)):
        self.ports = ports
        self.running = False
        self.threads = []

    def handle_connection(self, conn, addr, port):
        """Simulate a vulnerable service and log the payload."""
        ip, client_port = addr
        log.warning(f"HONEYPOT TRIGGERED: Connection from {ip}:{client_port} on port {port}")
        
        try:
            conn.settimeout(5.0)
            if port == 22:
                conn.sendall(b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n")
            elif port == 21:
                conn.sendall(b"220 (vsFTPd 3.0.3)\r\n")
            elif port == 8080:
                conn.sendall(b"HTTP/1.1 200 OK\r\nServer: Apache Tomcat/8.5.32\r\n\r\n")
            
            # Read payload
            payload = conn.recv(1024)
            if payload:
                payload_str = payload.decode('utf-8', errors='ignore').strip()
                log.warning(f"HONEYPOT PAYLOAD from {ip}: {payload_str}")
                
                # Log to the SOC Engine Database directly
                threat_db.insert_threat({
                    "event_id": f"HP-{int(time.time())}-{ip}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "timestamp_epoch": time.time(),
                    "source_ip": ip,
                    "source_port": client_port,
                    "destination_ip": "127.0.0.1",
                    "destination_port": port,
                    "protocol": "TCP",
                    "detection_method": "Active Honeypot Trap",
                    "confidence": 100.0,
                    "severity": 10.0,
                    "threat_type": "Honeypot Interaction",
                    "threat_intel": f"Captured payload: {payload_str[:200]}",
                    "mitre_technique_id": "T1190",
                    "mitre_tactic": "Initial Access"
                })
        except Exception as e:
            pass
        finally:
            conn.close()

    def listen_port(self, port):
        """Listen on a specific port for incoming connections."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(('0.0.0.0', port))
            s.listen(5)
            log.info(f"Honeypot actively listening on port {port}")
            while self.running:
                try:
                    s.settimeout(1.0)
                    conn, addr = s.accept()
                    threading.Thread(target=self.handle_connection, args=(conn, addr, port), daemon=True).start()
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception as e:
            log.error(f"Honeypot failed to bind port {port}: {e}")
        finally:
            s.close()

    def start(self):
        self.running = True
        for port in self.ports:
            t = threading.Thread(target=self.listen_port, args=(port,), daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        self.running = False
        for t in self.threads:
            t.join(timeout=2)
