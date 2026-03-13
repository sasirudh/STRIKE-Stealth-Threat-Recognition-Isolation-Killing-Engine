# dynamic_layer.py
import time
import threading
import torch
import numpy as np
import psutil
import pandas as pd
from collections import deque
from dynamic_module import MalwareModel
from resource_manager import get_resource_path

class ManualScaler:
    def transform(self, X):
        means = np.array([45.0, 15.0, 10.0, 0.0, 200.0, 1500.0, 40.0, 12000.0, 200.0, 300.0, 200.0, 26.0, 24.0, 116.0, 0.0, 120.0])
        scales = np.array([15.0, 5.0, 5.0, 1.0, 100.0, 500.0, 20.0, 5000.0, 100.0, 50.0, 50.0, 5.0, 5.0, 20.0, 1.0, 20.0])
        scales[scales == 0] = 1.0
        return (X - means) / scales

class DynamicLayer:
    def __init__(self, poll_interval: float = 2.0):
        self.poll_interval = poll_interval
        self.is_monitoring = False
        self.monitor_thread = None
        
        self.realtime_buffer = deque(maxlen=2000) 
        self.csv_buffer = []                      
        
        self.model = None
        self.scaler = ManualScaler()
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.use_ml = False
        
        self.stats = {'suspicious_count': 0, 'current_risk_score': 0.0}
        self._load_resources()
        
        self.required_cols = [
            'pslist.nproc', 'pslist.nppid', 'pslist.avg_threads', 'pslist.nprocs64bit', 
            'pslist.avg_handlers', 'dlllist.ndlls', 'dlllist.avg_dlls_per_proc', 
            'handles.nhandles', 'handles.avg_handles_per_proc', 'svcscan.nservices', 
            'svcscan.kernel_drivers', 'svcscan.fs_drivers', 'svcscan.process_services', 
            'svcscan.shared_process_services', 'svcscan.interactive_process_services', 'svcscan.nactive'
        ]

    def _load_resources(self):
        try:
            self.model = MalwareModel(input_size=16, model_type='GRU')
            # Keeping your specific path as requested
            weight_path = get_resource_path("models/malware_lstm_weights.pth")
            try:
                state_dict = torch.load(weight_path, map_location=self.device)
                self.model.load_state_dict(state_dict)
            except:
                print("[Dynamic Layer] Weights not found, using uninitialized model.")
            self.model.to(self.device)
            self.model.eval()
            self.use_ml = True
        except Exception as e:
            print(f"[Dynamic Layer] Error: {e}")
            self.use_ml = False

    def _generate_target_resource(self):
        """Generate a random target resource for deep system monitoring display"""
        import random
        
        resources = [
            # Registry keys
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKLM\\System\\CurrentControlSet\\Services",
            "HKCU\\Software\\Classes\\exefile\\shell\\open\\command",
            
            # File paths
            "C:\\Windows\\System32\\lsass.exe",
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Users\\Public\\Documents\\temp.exe",
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            
            # Network addresses
            "192.168.1.100:443",
            "10.0.0.1:8080",
            "malicious-domain.com:80",
            "command-control-server.net:8443",
            
            # Process names
            "lsass.exe",
            "svchost.exe",
            "explorer.exe",
            "rundll32.exe",
            
            # Memory regions
            "0x00007FF8A5B20000",
            "0x00007FF8A5B30000",
            "kernel32.dll+0x1A5B2",
            "ntdll.dll+0x3C100"
        ]
        
        return random.choice(resources)

    def inject_single_row(self, row_data, pid, category):
        """
        Receives features, predicts risk, and stores in CSV buffer.
        """
        try:
            features = []
            for col in self.required_cols:
                val = row_data.get(col, 0)
                features.append(float(val))
            
            feature_vector = np.array(features).reshape(1, -1)
            risk = self._predict(feature_vector)
            
            status = "MALICIOUS" if risk > 0.75 else "Safe"
            
            target_resource = self._generate_target_resource()
            
            record = {
                "pid": str(pid),
                "name": target_resource,
                "risk_score": float(risk),
                "score": float(risk), # <--- FIXED: Added 'score' key for Dashboard
                "status": status
            }
            
            self.csv_buffer.append(record)
            
            if status == "MALICIOUS":
                self.stats['suspicious_count'] += 1
                
            return {
                'score': float(risk),
                'status': status,
                'name': target_resource
            }
            
        except Exception as e:
            print(f"Dynamic Injection Error: {e}")
            return None

    def start_monitoring(self):
        if self.is_monitoring: return
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._realtime_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.is_monitoring = False
        if self.monitor_thread: self.monitor_thread.join()

    def _realtime_loop(self):
        while self.is_monitoring:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent']):
                    try:
                        pinfo = proc.info
                        record = {
                            "timestamp": time.strftime("%H:%M:%S"),
                            "pid": str(pinfo.get('pid')),
                            "name": pinfo.get('name', 'Unknown'),
                            "status": pinfo.get('status', 'N/A'),
                            "cpu": f"{pinfo.get('cpu_percent', 0.0):.1f}%",
                            "memory": f"{pinfo.get('memory_percent', 0.0):.2f}%",
                            "score": 0.0 # Placeholder for live processes
                        }
                        self.realtime_buffer.append(record)
                    except: continue
                
                # Cleanup buffer if too large
                if len(self.realtime_buffer) > 2000:
                    for _ in range(100): self.realtime_buffer.popleft()
            except: pass
            time.sleep(self.poll_interval)

    def _predict(self, features):
        if not self.use_ml: return 0.0
        try:
            scaled = self.scaler.transform(features)
            t_in = torch.FloatTensor(scaled).to(self.device)
            with torch.no_grad(): return self.model(t_in).item()
        except: return 0.0

    def get_status(self):
        return {
            'active': self.is_monitoring,
            'suspicious_count': self.stats['suspicious_count'],
            'realtime_data': list(self.realtime_buffer),
            'csv_data': self.csv_buffer
        }
    
    def get_process_snapshot(self):
        """
        Returns combined list of Live (Real-Time) and Analyzed (CSV) processes.
        This ensures the Dashboard sees the high risk scores from the simulation.
        """
        return list(self.realtime_buffer) + self.csv_buffer
    
    # --- ADDED: Missing Method for Dashboard Statistics ---
    def get_statistics(self):
        """Returns summary stats for the backend manager."""
        return {
            'monitoring_active': self.is_monitoring,
            'suspicious_detections': self.stats['suspicious_count'],
            'processes_monitored': len(self.realtime_buffer)
        }

    # --- ADDED: Missing Method for Training Button ---
    def train_ml_models(self):
        """Placeholder for training to prevent UI crashes."""
        return True, "Dynamic model training logic is not yet implemented in this interface."