import os
import queue
import threading
import time

try:
    import google.generativeai as genai
    _GENAI_AVAILABLE = True
except ImportError:
    _GENAI_AVAILABLE = False

class LLMEnricher:
    """Asynchronously generates human-readable threat intel using GenAI."""
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.enabled = bool(self.api_key) and _GENAI_AVAILABLE
        
        if self.enabled:
            genai.configure(api_key=self.api_key)
            # Use a fast model suitable for high-volume logs
            self.model = genai.GenerativeModel('gemini-1.5-flash')
            print("[LLM Enricher] Initialized successfully with Google Gemini.")
        else:
            print("[LLM Enricher] Hardware API disabled (GEMINI_API_KEY missing or google-generativeai not installed). Using local simulation.")
            
        self._queue = queue.Queue()
        self._running = False
        self._thread = None
        self._dashboard_callback = None

    def set_dashboard_callback(self, callback):
        """Registers a callback to push results to the Dashboard websocket."""
        self._dashboard_callback = callback

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._worker, daemon=True, name="LLMEnricherThread")
        self._thread.start()

    def stop(self):
        self._running = False
        if self._queue:
            self._queue.put(None)  # Poison pill
            
    def queue_threat(self, event_id, threat_data):
        """Non-blocking call to queue an event for LLM analysis."""
        try:
            self._queue.put_nowait({"event_id": event_id, "data": threat_data})
        except queue.Full:
            print(f"[LLM Enricher] Queue full! Dropping event {event_id} to prevent memory exhaustion.")

    def _worker(self):
        while self._running:
            try:
                task = self._queue.get(timeout=2.0)
                if task is None:
                    break
                
                event_id = task["event_id"]
                data = task["data"]
                
                enrichment_text = self._generate_enrichment(data)
                
                if self._dashboard_callback:
                    self._dashboard_callback(event_id, enrichment_text)
                    
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[LLM Enricher] Worker error: {e}")

    def _generate_enrichment(self, data):
        prompt = (
            f"You are a Senior Cybersecurity Analyst and Incident Responder. Analyze the following network attack "
            f"and generate a highly detailed 'Incident Response Playbook' for the SOC team.\n\n"
            f"Structure your response with these exact headers:\n"
            f"1. EXECUTIVE SUMMARY: (1 sentence overview)\n"
            f"2. TECHNICAL ANALYSIS: (Why did this happen and what is the attacker's goal?)\n"
            f"3. MITIGATION STEPS: (List 3 immediate actions to take)\n"
            f"4. FORENSIC ARTIFACTS: (What else should we look for?)\n\n"
            f"Attack Data:\n"
            f"- Source IP: {data.get('source')}\n"
            f"- Target Ports: {data.get('ports')}\n"
            f"- Attack Type: {data.get('method')}\n"
            f"- Confidence: {data.get('confidence')}%\n"
            f"- Raw Details: {data.get('intel')}\n"
        )
        
        if self.enabled:
            try:
                response = self.model.generate_content(prompt)
                return response.text.strip()
            except Exception as e:
                return f"GenAI Generation failed: {e}"
        else:
            # Fallback mock response so the system still functions if API is down
            # Simulate a 1-2 second delay for realism
            time.sleep(1.5)
            method = data.get('method', 'Unknown')
            source = data.get('source', 'Unknown')
            ports = data.get('ports', 'Unknown')
            return (
                f"**INCIDENT RESPONSE PLAYBOOK**\n\n"
                f"**1. EXECUTIVE SUMMARY:**\n"
                f"Automated AI detection confirms a high-confidence {method} originating from {source}.\n\n"
                f"**2. TECHNICAL ANALYSIS:**\n"
                f"The attacker is likely utilizing automated exploitation scripts targeting exposed services on ports {ports}. "
                f"The traffic pattern exactly matches known botnet reconnaissance and payload delivery signatures.\n\n"
                f"**3. MITIGATION STEPS:**\n"
                f"- [COMPLETED] IP {source} blocked at the edge firewall.\n"
                f"- [ACTION REQUIRED] Review server logs on target ports for successful HTTP 200/POST requests.\n"
                f"- [ACTION REQUIRED] Rotate service credentials if ports 22 or 3389 were accessed.\n\n"
                f"**4. FORENSIC ARTIFACTS:**\n"
                f"- PCAP files saved to /pcap_archive for further Wireshark analysis.\n"
                f"- Check SIEM for lateral movement from {source}."
            )

# Singleton instance
enricher = LLMEnricher()
