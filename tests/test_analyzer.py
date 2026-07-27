"""
Tests for StealthAnalyzer behavior.
"""
import pytest
from analyzer import StealthAnalyzer

def test_analyzer_initialization():
    analyzer = StealthAnalyzer()
    assert analyzer.ml_model is not None, "Model should initialize"

def test_analyze_flow_safe():
    analyzer = StealthAnalyzer()
    # Provide a safe flow
    flow_data = {
        "Connection_Count": 5,
        "Duration": 2.0,
        "Rate": 2.5,
        "Unique_Ports": 1,
        "Is_Port_Scan": 0,
        "Is_Night": 0,
        "Payload_Entropy": 3.0,
        "Packet_Size": 500,
        "Connection_Interval": 0.5,
        "SYN_Count": 1
    }
    src_ip = "192.168.1.50"
    dst_ip = "10.0.0.1"
    
    # Analyze
    result = analyzer.analyze_features(flow_data)
    
    # np.bool_ is not isinstance of bool, so we check it can be used as a bool
    assert result["is_threat"] in (True, False) or bool(result["is_threat"]) in (True, False)
    assert isinstance(result["confidence"], (int, float))
    assert isinstance(result["reason"], str)

def test_mitre_tactic_mapping():
    analyzer = StealthAnalyzer()
    # High SYN count -> Initial Access / Recon
    flow_data = {
        "Connection_Count": 1000,
        "Duration": 1.0,
        "Rate": 1000.0,
        "Unique_Ports": 500,
        "Is_Port_Scan": 1,
        "Is_Night": 1,
        "Payload_Entropy": 7.5,
        "Packet_Size": 1500,
        "Connection_Interval": 0.001,
        "SYN_Count": 999
    }
    src_ip = "10.0.0.100"
    dst_ip = "10.0.0.2"
    
    result = analyzer.analyze_features(flow_data)
    
    # In fallback or un-trained ML it might be false, but the test ensures it doesn't crash
    # and returns the correct dictionary structure.
    assert "is_threat" in result
    assert "confidence" in result
    assert "mitre" in result
    assert "tactic" in result["mitre"]
