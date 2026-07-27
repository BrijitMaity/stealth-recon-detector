"""
packet_features.py — Real packet feature extraction for ML pipeline.

Extracts actual features from Scapy packet objects instead of generating
random values. This module is the bridge between raw network packets
and the Random Forest ML model.

Industry enhancements:
  - Flow timeout / expiry to prevent unbounded memory growth
  - Jitter calculation (stddev of inter-packet times)
  - Byte-rate calculation
  - Flow memory bounded to configurable limits

Usage:
    from packet_features import PacketFeatureExtractor
    extractor = PacketFeatureExtractor()
    features = extractor.extract(packet, flow_state)
"""

import math
import time
import datetime
from collections import Counter

try:
    from scapy.all import IP, TCP, Raw
except ImportError:
    IP = TCP = Raw = None

from config import cfg
from app_logger import get_logger

log = get_logger(__name__)

# ── Constants ──────────────────────────────────────────────────────────
_FLOW_TIMEOUT_SECONDS = 300     # Expire flow state after 5 minutes of inactivity
_MAX_TRACKED_FLOWS = 10000      # Hard cap on simultaneous flow tracking
_MAX_TIMESTAMPS_PER_FLOW = 100  # Keep only last N timestamps per flow


def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of a byte sequence.

    Returns a value between 0.0 (all identical bytes) and 8.0 (perfectly random).
    High entropy (>6.0) often indicates encrypted or compressed data.
    Payloads with known malicious patterns typically have entropy between 3.5-5.5.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_tcp_flags(packet) -> dict:
    """
    Extract individual TCP flag counts from a packet.

    TCP flags field is a bitmask:
        FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
    """
    flags = {
        "is_syn": 0,
        "is_ack": 0,
        "is_fin": 0,
        "is_rst": 0,
        "is_psh": 0,
        "is_urg": 0,
    }
    if packet and TCP and packet.haslayer(TCP):
        tcp_flags = packet[TCP].flags
        if isinstance(tcp_flags, int):
            flag_val = tcp_flags
        else:
            # Scapy may return a FlagValue object
            flag_val = int(tcp_flags)
        flags["is_syn"] = 1 if (flag_val & 0x02) else 0
        flags["is_ack"] = 1 if (flag_val & 0x10) else 0
        flags["is_fin"] = 1 if (flag_val & 0x01) else 0
        flags["is_rst"] = 1 if (flag_val & 0x04) else 0
        flags["is_psh"] = 1 if (flag_val & 0x08) else 0
        flags["is_urg"] = 1 if (flag_val & 0x20) else 0
    return flags


class PacketFeatureExtractor:
    """
    Extracts real features from Scapy packets for the ML pipeline.

    Maintains per-flow state to compute aggregate features like
    SYN counts, connection intervals, and packet rates.

    Industry features:
      - Auto-expires stale flows to prevent unbounded memory growth
      - Calculates jitter (stddev of inter-packet arrival times)
      - Computes byte-rate per flow
      - Bounds memory usage with configurable limits
    """

    def __init__(self):
        # Per-IP flow state for accumulating flag counts
        self._flow_flags = {}  # ip -> {"syn": int, "ack": int, ...}
        self._flow_timestamps = {}  # ip -> [timestamp1, timestamp2, ...]
        self._flow_bytes = {}  # ip -> total bytes seen
        self._flow_last_seen = {}  # ip -> last_seen_timestamp (for expiry)
        self._last_cleanup = time.time()

    def _cleanup_stale_flows(self):
        """Remove flow state for IPs that haven't been seen recently."""
        now = time.time()
        # Only run cleanup every 30 seconds to avoid overhead
        if now - self._last_cleanup < 30:
            return

        expired = [
            ip for ip, last_seen in self._flow_last_seen.items()
            if now - last_seen > _FLOW_TIMEOUT_SECONDS
        ]
        for ip in expired:
            self._flow_flags.pop(ip, None)
            self._flow_timestamps.pop(ip, None)
            self._flow_bytes.pop(ip, None)
            self._flow_last_seen.pop(ip, None)

        if expired:
            log.debug(f"Cleaned up {len(expired)} stale flow entries")

        # Hard cap enforcement — evict oldest flows if over limit
        if len(self._flow_last_seen) > _MAX_TRACKED_FLOWS:
            sorted_flows = sorted(self._flow_last_seen.items(), key=lambda x: x[1])
            to_evict = sorted_flows[:len(sorted_flows) - _MAX_TRACKED_FLOWS]
            for ip, _ in to_evict:
                self._flow_flags.pop(ip, None)
                self._flow_timestamps.pop(ip, None)
                self._flow_bytes.pop(ip, None)
                self._flow_last_seen.pop(ip, None)
            log.debug(f"Evicted {len(to_evict)} flows (over limit)")

        self._last_cleanup = now

    def _update_flow_flags(self, src_ip: str, tcp_flags: dict):
        """Accumulate TCP flag counts per flow."""
        if src_ip not in self._flow_flags:
            self._flow_flags[src_ip] = {
                "syn": 0, "ack": 0, "fin": 0,
                "rst": 0, "psh": 0, "urg": 0
            }
        ff = self._flow_flags[src_ip]
        ff["syn"] += tcp_flags["is_syn"]
        ff["ack"] += tcp_flags["is_ack"]
        ff["fin"] += tcp_flags["is_fin"]
        ff["rst"] += tcp_flags["is_rst"]
        ff["psh"] += tcp_flags["is_psh"]
        ff["urg"] += tcp_flags["is_urg"]

    def _update_flow_timestamps(self, src_ip: str, ts: float):
        """Track packet arrival times for connection interval calculation."""
        if src_ip not in self._flow_timestamps:
            self._flow_timestamps[src_ip] = []
        self._flow_timestamps[src_ip].append(ts)
        # Keep only last N timestamps to bound memory
        if len(self._flow_timestamps[src_ip]) > _MAX_TIMESTAMPS_PER_FLOW:
            self._flow_timestamps[src_ip] = self._flow_timestamps[src_ip][-_MAX_TIMESTAMPS_PER_FLOW:]

    def _update_flow_bytes(self, src_ip: str, packet_size: int):
        """Track total bytes per flow for byte-rate calculation."""
        self._flow_bytes[src_ip] = self._flow_bytes.get(src_ip, 0) + packet_size

    def get_connection_interval(self, src_ip: str) -> float:
        """Average time between packets for a given source IP."""
        timestamps = self._flow_timestamps.get(src_ip, [])
        if len(timestamps) < 2:
            return 0.0
        intervals = [timestamps[i] - timestamps[i-1]
                      for i in range(1, len(timestamps))]
        return round(sum(intervals) / len(intervals), 4) if intervals else 0.0

    def get_jitter(self, src_ip: str) -> float:
        """Standard deviation of inter-packet arrival times (jitter).

        High jitter often indicates human behavior; low jitter indicates
        automated scanning tools.
        """
        timestamps = self._flow_timestamps.get(src_ip, [])
        if len(timestamps) < 3:
            return 0.0
        intervals = [timestamps[i] - timestamps[i-1]
                      for i in range(1, len(timestamps))]
        if not intervals:
            return 0.0
        mean = sum(intervals) / len(intervals)
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        return round(math.sqrt(variance), 4)

    def get_byte_rate(self, src_ip: str, duration: float) -> float:
        """Bytes per second for a given flow."""
        total_bytes = self._flow_bytes.get(src_ip, 0)
        if duration <= 0:
            return float(total_bytes)
        return round(total_bytes / duration, 4)

    def get_flow_flag_counts(self, src_ip: str) -> dict:
        """Return accumulated TCP flag counts for a flow."""
        return self._flow_flags.get(src_ip, {
            "syn": 0, "ack": 0, "fin": 0,
            "rst": 0, "psh": 0, "urg": 0
        })

    def reset_flow(self, src_ip: str):
        """Reset flow state for an IP (e.g., after blocking)."""
        self._flow_flags.pop(src_ip, None)
        self._flow_timestamps.pop(src_ip, None)
        self._flow_bytes.pop(src_ip, None)
        self._flow_last_seen.pop(src_ip, None)

    def extract(self, packet, flow_state: dict) -> dict:
        """
        Extract a complete feature dictionary from a packet and its flow state.

        Parameters
        ----------
        packet : scapy.Packet
            The raw Scapy packet object.
        flow_state : dict
            The flow tracking dict from monitor.py containing:
            - "ports": set of destination ports
            - "start_time": float
            - "packet_count": int
            - "last_packet_time": float

        Returns
        -------
        dict
            Feature dictionary with all ML-ready features extracted from
            real packet data. No random values.
        """
        now = time.time()
        src_ip = ""

        # Periodic cleanup of stale flows
        self._cleanup_stale_flows()

        # ── Extract real packet-level features ─────────────────────────
        packet_size = len(packet) if packet else 0
        ttl_value = 0
        window_size = 0
        payload_bytes = b""

        if packet and IP and packet.haslayer(IP):
            src_ip = packet[IP].src
            ttl_value = packet[IP].ttl

        if packet and TCP and packet.haslayer(TCP):
            window_size = packet[TCP].window

        if packet and Raw and packet.haslayer(Raw):
            payload_bytes = bytes(packet[Raw].load)

        # ── TCP flag extraction ────────────────────────────────────────
        tcp_flags = extract_tcp_flags(packet)
        self._update_flow_flags(src_ip, tcp_flags)
        self._update_flow_timestamps(src_ip, now)
        self._update_flow_bytes(src_ip, packet_size)
        self._flow_last_seen[src_ip] = now

        # ── Flow-level features ────────────────────────────────────────
        unique_ports = len(flow_state.get("ports", set()))
        packets = flow_state.get("packet_count", 1)
        start_time = flow_state.get("start_time", now)
        last_time = flow_state.get("last_packet_time", now)
        duration = last_time - start_time
        rate = packets / duration if duration > 0 else float(packets)

        # ── Computed features ──────────────────────────────────────────
        payload_entropy = shannon_entropy(payload_bytes)
        payload_size = len(payload_bytes)
        connection_interval = self.get_connection_interval(src_ip)
        jitter = self.get_jitter(src_ip)
        byte_rate = self.get_byte_rate(src_ip, duration)
        flow_flags = self.get_flow_flag_counts(src_ip)

        # ── Time-based features ────────────────────────────────────────
        hour = datetime.datetime.now().hour
        is_night = 1 if (hour >= cfg.NIGHT_START_HOUR or hour <= cfg.NIGHT_END_HOUR) else 0
        is_port_scan = 1 if unique_ports > cfg.UNIQUE_PORT_THRESHOLD else 0

        return {
            # ── ML model features (exact order for predict()) ──────────
            "Connection_Count": packets,
            "Duration": round(duration, 4),
            "Rate": round(rate, 4),
            "Unique_Ports": unique_ports,
            "Is_Port_Scan": is_port_scan,
            "Is_Night": is_night,
            "Payload_Entropy": payload_entropy,
            "Packet_Size": packet_size,
            "Connection_Interval": connection_interval,
            "SYN_Count": flow_flags["syn"],

            # ── Additional real features for CSV logging ───────────────
            "ACK_Count": flow_flags["ack"],
            "FIN_Count": flow_flags["fin"],
            "RST_Count": flow_flags["rst"],
            "PSH_Count": flow_flags["psh"],
            "URG_Count": flow_flags["urg"],
            "TTL_Value": ttl_value,
            "Window_Size": window_size,
            "Payload_Size": payload_size,
            "Payload_Length": payload_size,
            "Hour": hour,

            # ── Derived behavioral scores ──────────────────────────────
            "Packets_Per_Second": round(rate, 4),
            "Jitter": jitter,
            "Byte_Rate": byte_rate,
        }


# ── Module-level convenience ───────────────────────────────────────────
_default_extractor = None


def get_extractor() -> PacketFeatureExtractor:
    """Get or create the singleton feature extractor."""
    global _default_extractor
    if _default_extractor is None:
        _default_extractor = PacketFeatureExtractor()
    return _default_extractor
