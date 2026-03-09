# backend_manager.py
"""
------------------------------------------------------------------------------
 Project: Detection and elimination of stealthy malware variants using deep learning algorithms 
 File : Main_ui
 Author:  Sasirudh Ponneri Balaji & Sairahul S
 Date:    February 2026
 
 Copyright (c) 2026 Sasirudh Ponneri Balaji &. All rights reserved.
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 This code is proprietary and confidential. Unauthorized copying of this file,
 via any medium, is strictly prohibited.
------------------------------------------------------------------------------
"""

import os
import time
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class DetectionResult:
    """Unified detection result from any layer"""
    timestamp: float
    layer: str  # "static", "dynamic", or "network"
    score: float  # 0.0 to 1.0
    label: str  # "Benign", "Suspicious", "Malicious"
    details: Dict[str, Any] = field(default_factory=dict)
    target: Optional[str] = None  # file path, PID, or IP

@dataclass
class EnsembleResult:
    """Combined result from all three layers"""
    timestamp: float
    static_score: float
    dynamic_score: float
    network_score: float
    combined_score: float
    label: str
    confidence: float
    reason: str

class BackendManager:
    """
    Central coordinator for all three detection layers.
    Manages the lifecycle and orchestrates scanning across layers.
    """
    
    def __init__(self):
        self.static_layer = None
        self.dynamic_layer = None
        self.network_layer = None
        
        # Ensemble weights
        self.weights = {
            'static': 0.3,
            'dynamic': 0.4,
            'network': 0.3
        }
        
        # History
        self.detection_history: List[DetectionResult] = []
        self.ensemble_history: List[EnsembleResult] = []
        self.alerts: List[Dict[str, Any]] = []
        
        # Monitoring state
        self.is_monitoring = False
        
    def initialize_layers(self):
        """Initialize all detection layers"""
        from static_layer import StaticLayer
        from dynamic_layer import DynamicLayer
        from network_layer import NetworkLayer
        
        self.static_layer = StaticLayer()
        self.dynamic_layer = DynamicLayer()
        self.network_layer = NetworkLayer()
        
    def scan_static(self, file_path: str) -> DetectionResult:
        """Perform static analysis on a file"""
        if not self.static_layer:
            raise RuntimeError("Static layer not initialized")
        
        result = self.static_layer.scan_file(file_path)
        
        detection = DetectionResult(
            timestamp=time.time(),
            layer="static",
            score=result['score'],
            label=result['label'],
            details=result['details'],
            target=file_path
        )
        
        self.detection_history.append(detection)
        return detection
    
    def get_dynamic_snapshot(self) -> Tuple[List[Dict], float]:
        """Get current dynamic (process) analysis snapshot"""
        if not self.dynamic_layer:
            raise RuntimeError("Dynamic layer not initialized")
        
        processes = self.dynamic_layer.get_process_snapshot()
        max_score = max([p['score'] for p in processes], default=0.0)
        
        return processes, max_score
    
    def get_network_snapshot(self) -> Tuple[Dict, float]:
        """Get current network analysis snapshot"""
        if not self.network_layer:
            raise RuntimeError("Network layer not initialized")
        
        stats = self.network_layer.get_network_stats()
        
        return stats, stats['score']
    
    # backend_manager.py (Partial Update - Replace analyze_network_pcap)

    def analyze_traffic_file(self, file_path: str) -> DetectionResult:
        """Analyze a CSV or PCAP file and switch to simulation mode"""
        if not self.network_layer:
            raise RuntimeError("Network layer not initialized")
        
        # Call the new generic function
        results = self.network_layer.analyze_file(file_path)
        
        if 'error' in results:
            raise RuntimeError(results['error'])
            
        score = results['risk_score']
        label = "Malicious" if score > 0.5 else "Benign"
        
        detection = DetectionResult(
            timestamp=time.time(),
            layer="network",
            score=score,
            label=label,
            details=results,
            target=file_path
        )
        
        self.detection_history.append(detection)
        
        if label == "Malicious":
            self.add_alert("Network Threat", score, f"Found {results['malicious_flows']} malicious flows in traffic file")
            
        return detection
    
    def compute_ensemble(self, static_score: float = 0.0, 
                        dynamic_score: float = 0.0, 
                        network_score: float = 0.0) -> EnsembleResult:
        """
        Combine scores from all layers into ensemble decision.
        """
        combined = (
            self.weights['static'] * static_score +
            self.weights['dynamic'] * dynamic_score +
            self.weights['network'] * network_score
        )
        
        # Determine label
        if combined >= 0.75:
            label = "Malicious"
            confidence = combined
        elif combined >= 0.4:
            label = "Suspicious"
            confidence = combined
        else:
            label = "Benign"
            confidence = 1.0 - combined
        
        reason = f"Static:{static_score:.2f} Dynamic:{dynamic_score:.2f} Network:{network_score:.2f}"
        
        result = EnsembleResult(
            timestamp=time.time(),
            static_score=static_score,
            dynamic_score=dynamic_score,
            network_score=network_score,
            combined_score=combined,
            label=label,
            confidence=confidence,
            reason=reason
        )
        
        self.ensemble_history.append(result)
        
        # Create alert if suspicious or malicious
        if label in ("Suspicious", "Malicious"):
            self.add_alert(label, confidence, reason)
        
        return result
    
    

    def add_alert(self, label: str, confidence: float, reason: str):
        """Add an alert to the alert list"""
        alert = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'label': label,
            'confidence': round(confidence, 3),
            'reason': reason
        }
        self.alerts.insert(0, alert)  # Most recent first
        
        # Keep only last 100 alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[:100]
    
    def get_alerts(self):
        return list(self.alerts)


    def start_monitoring(self):
        """Start continuous monitoring"""
        if not all([self.static_layer, self.dynamic_layer, self.network_layer]):
            raise RuntimeError("All layers must be initialized before monitoring")
        
        self.is_monitoring = True
        self.dynamic_layer.start_monitoring()
        self.network_layer.start_monitoring()
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.is_monitoring = False
        if self.dynamic_layer:
            self.dynamic_layer.stop_monitoring()
        if self.network_layer:
            self.network_layer.stop_monitoring()
    
    def quarantine_file(self, file_path: str, quarantine_dir: str = "quarantine") -> Tuple[bool, str]:
        """Move a file to quarantine"""
        if self.static_layer:
            return self.static_layer.quarantine_file(file_path, quarantine_dir)
        return False, "Static layer not initialized"
    
    def terminate_process(self, pid: int) -> Tuple[bool, str]:
        """Terminate a process"""
        if self.dynamic_layer:
            return self.dynamic_layer.terminate_process(pid)
        return False, "Dynamic layer not initialized"
    
    def block_ip(self, ip: str) -> Tuple[bool, str]:
        """Block an IP address"""
        if self.network_layer:
            return self.network_layer.block_ip(ip)
        return False, "Network layer not initialized"
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        stats = {
            'total_detections': len(self.detection_history),
            'total_alerts': len(self.alerts),
            'monitoring_active': self.is_monitoring,
        }
        
        if self.static_layer:
            stats['static'] = self.static_layer.get_statistics()
        
        if self.dynamic_layer:
            stats['dynamic'] = self.dynamic_layer.get_statistics()
        
        if self.network_layer:
            stats['network'] = self.network_layer.get_statistics()
        
        return stats
    
    def export_logs(self, file_path: str) -> Tuple[bool, str]:
        """Export all logs to CSV"""
        import csv
        
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Layer', 'Score', 'Label', 'Target', 'Details'])
                
                for detection in self.detection_history:
                    ts = datetime.fromtimestamp(detection.timestamp).strftime("%Y-%m-%d %H:%M:%S")
                    writer.writerow([
                        ts,
                        detection.layer,
                        detection.score,
                        detection.label,
                        detection.target or "N/A",
                        str(detection.details)
                    ])
            
            return True, f"Exported {len(self.detection_history)} detections"
        except Exception as e:
            return False, str(e)
    
    def train_all_ml_models(self) -> Dict[str, Tuple[bool, str]]:
        """Train all ML models on synthetic data"""
        results = {}
        
        if self.static_layer:
            results['static'] = self.static_layer.train_ml_model()
        else:
            results['static'] = (False, "Layer not initialized")
        
        if self.dynamic_layer:
            results['dynamic'] = self.dynamic_layer.train_ml_models()
        else:
            results['dynamic'] = (False, "Layer not initialized")
        
        if self.network_layer:
            results['network'] = self.network_layer.train_ml_model()
        else:
            results['network'] = (False, "Layer not initialized")
        
        return results
    
    def get_ml_status(self) -> Dict[str, bool]:
        """Get ML model status for each layer"""
        return {
            'static': self.static_layer.use_ml if self.static_layer else False,
            'dynamic': self.dynamic_layer.use_ml if self.dynamic_layer else False,
            'network': self.network_layer.use_ml if self.network_layer else False
        }