"""
ml_engine.py — Machine Learning Anomaly Detection (Isolation Forest)
"""

import os
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import threading
from app_logger import get_logger
from config import cfg

log = get_logger(__name__)

class MLEngine:
    def __init__(self, log_csv_path=None):
        self.log_csv_path = log_csv_path or cfg.LOG_CSV
        self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        self.is_trained = False
        self.lock = threading.Lock()
        
        # In-memory buffer for real-time training adaptation
        self.recent_traffic = []
        self.MAX_BUFFER = 1000
        
        # Start background training thread
        threading.Thread(target=self._initial_train, daemon=True).start()

    def _initial_train(self):
        """Train the model on historical CSV logs if available."""
        with self.lock:
            if not os.path.exists(self.log_csv_path):
                log.info("ML Engine: No historical data found. Waiting for real-time traffic to train.")
                return

            try:
                # Load up to 10k recent logs
                df = pd.read_csv(self.log_csv_path, on_bad_lines='skip', low_memory=False)
                if df.empty or 'Packet_Size' not in df.columns:
                    return

                # Extract all 10 features for 100% parity with random forest model
                required_cols = [
                    'Connection_Count', 'Duration', 'Rate', 'Unique_Ports', 'Is_Port_Scan',
                    'Is_Night', 'Payload_Entropy', 'Packet_Size', 'Connection_Interval', 'SYN_Count'
                ]
                
                feature_arrays = []
                for col in required_cols:
                    if col in df.columns:
                        feature_arrays.append(df[col].fillna(0).astype(float).values)
                    else:
                        feature_arrays.append(np.zeros(len(df)))
                
                X = np.column_stack(feature_arrays)
                
                # Limit to 10,000 for quick training
                if len(X) > 10000:
                    X = X[-10000:]

                self.model.fit(X)
                self.is_trained = True
                log.info(f"ML Engine: Initial Isolation Forest trained on {len(X)} historical records.")
            except Exception as e:
                log.error(f"ML Engine: Failed to train on historical data: {e}")

    def analyze_packet(self, feat_dict):
        """
        Analyze a real-time packet for anomalies using 10 features.
        Returns: (is_anomaly: bool, confidence: float)
        """
        features = [
            feat_dict.get("Connection_Count", 0),
            feat_dict.get("Duration", 0.0),
            feat_dict.get("Rate", 0.0),
            feat_dict.get("Unique_Ports", 0),
            feat_dict.get("Is_Port_Scan", 0),
            feat_dict.get("Is_Night", 0),
            feat_dict.get("Payload_Entropy", 0.0),
            feat_dict.get("Packet_Size", 0),
            feat_dict.get("Connection_Interval", 0.0),
            feat_dict.get("SYN_Count", 0)
        ]

        # Save to buffer for future retraining
        with self.lock:
            self.recent_traffic.append(features)
            if len(self.recent_traffic) > self.MAX_BUFFER:
                self.recent_traffic.pop(0)

            # If not trained yet, try to train on the buffer if it has enough data
            if not self.is_trained and len(self.recent_traffic) >= 50:
                self.model.fit(self.recent_traffic)
                self.is_trained = True
                log.info(f"ML Engine: Warm-started on {len(self.recent_traffic)} live packets.")

        # If still not trained, assume it's normal
        if not self.is_trained:
            return False, 0.0

        try:
            X_test = np.array([features])
            # predict returns 1 for normal, -1 for anomaly
            prediction = self.model.predict(X_test)[0]
            
            # decision_function returns average anomaly score
            # Lower means more anomalous
            score = self.model.decision_function(X_test)[0]
            
            # Map score to a 0-100% confidence level
            # Typical scores are between -0.5 and 0.5. 
            # If prediction == -1, it's an anomaly.
            is_anomaly = (prediction == -1)
            
            # Convert decision score to a pseudo-probability (0 to 100)
            # More negative score = higher confidence it's an anomaly
            if is_anomaly:
                confidence = min(100.0, max(0.0, abs(score) * 200 + 50))
            else:
                confidence = 0.0

            return is_anomaly, round(confidence, 1)

        except Exception as e:
            log.error(f"ML Engine: Analysis error: {e}")
            return False, 0.0

# Singleton instance
ml_engine = MLEngine()
