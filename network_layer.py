# network_layer.py
import os
import time
import psutil
import threading
import pandas as pd
import numpy as np
import onnxruntime as rt
import random
from collections import defaultdict, deque
from resource_manager import get_resource_path

class NetworkLayer:
    def __init__(self, poll_interval: float = 1.0):
        self.poll_interval = poll_interval
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Separate Buffers
        self.live_buffer = deque(maxlen=2000) 
        self.sim_buffer = [] 
        
        self.proc_ip_map = {}
        self.live_ip_stats = defaultdict(lambda: {'connections': 0})
        self.bandwidth = 0.0
        self.last_io = None
        self.last_time = None
        
        # ML Setup
        self.ml_session = None
        self.use_ml = False
        self.model_path = get_resource_path("models/stealthy_malware_pipeline.onnx") # Your ONNX model path
        self._try_load_ml_model()

        # Features required by ONNX model
        self.required_cols = [
            'Destination Port', 'Flow Duration', 'Total Length of Fwd Packets', 
            'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 
            'Bwd Packet Length Mean', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 
            'Flow IAT Max', 'Fwd Header Length', 'Bwd Header Length', 'Bwd Packets/s', 
            'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 
            'Packet Length Variance', 'Average Packet Size', 'Avg Fwd Segment Size', 
            'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Subflow Fwd Bytes', 
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward'
        ]

    def _try_load_ml_model(self):
        try:
            if os.path.exists(self.model_path):
                self.ml_session = rt.InferenceSession(self.model_path)
                self.input_name = self.ml_session.get_inputs()[0].name
                self.use_ml = True
                print(f"[Network] Model Loaded: {self.model_path}")
            else:
                print(f"[Network] Model not found at {self.model_path}")
        except Exception as e:
            print(f"[Network] ML Error: {e}")

    # ==========================================
    # 1. LIVE MONITORING (Real Hardware)
    # ==========================================
    def start_monitoring(self):
        if self.is_monitoring: return
        
        self.live_buffer.clear()
        self.sim_buffer = [] 
        self.live_ip_stats.clear()
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print("[Network] Live Monitoring Started.")

    def stop_monitoring(self):
        self.is_monitoring = False
        if self.monitor_thread: self.monitor_thread.join(timeout=1.0)

    def _monitor_loop(self):
        while self.is_monitoring:
            try:
                # A. Bandwidth
                now = time.time()
                io = psutil.net_io_counters()
                if self.last_io and self.last_time:
                    dt = now - self.last_time
                    if dt > 0:
                        self.bandwidth = (io.bytes_sent + io.bytes_recv - self.last_io.bytes_sent - self.last_io.bytes_recv) / dt
                self.last_io = io
                self.last_time = now

                # B. Active Connections
                # DEBUG: Print to check if loop runs
                # print("[DEBUG] Network Loop Running...") 
                
                try:
                    # Get ALL tcp/udp connections
                    conns = psutil.net_connections(kind='inet')
                    
                    if not conns:
                        print("[DEBUG] psutil returned 0 connections (Check Permissions?)")

                    for c in conns:
                        # We want anything with a remote address (actual traffic)
                        if c.raddr:
                            # Safely handle PID
                            pid_val = str(c.pid) if c.pid else "System"
                            
                            # Format Data
                            record = {
                                "time": time.strftime("%H:%M:%S"),
                                "local": f"{c.laddr.ip}:{c.laddr.port}",
                                "remote": f"{c.raddr.ip}:{c.raddr.port}",
                                "status": c.status,
                                "pid": pid_val
                            }
                            
                            self.live_buffer.append(record)
                            self.live_ip_stats[c.raddr.ip]['connections'] += 1
                            
                except psutil.AccessDenied:
                    print("[DEBUG] Access Denied to network connections. Try running as Admin.")
                except Exception as e:
                    print(f"[DEBUG] Connection Fetch Error: {e}")
                
                # Limit buffer
                if len(self.live_buffer) > 2000:
                    pass 

            except Exception as e:
                print(f"[Network Loop Critical Error] {e}")
            
            time.sleep(self.poll_interval)

    # ==========================================
    # 2. SIMULATION INJECTION (CSV Feed)
    # ==========================================
    def inject_single_row(self, row_data, pid):
        try:
            risk = 0.0
            status = "Safe"
            
            if self.use_ml:
                vals = [float(row_data.get(c, 0)) for c in self.required_cols]
                X = np.array(vals, dtype=np.float32).reshape(1, -1)
                outs = self.ml_session.run(None, {self.input_name: X})
                risk = outs[1][0].get(1, 0.0) if isinstance(outs[1], list) else outs[1][0][1]
            
            if risk > 0.5: status = "MALICIOUS"
            
            dst_port = int(row_data.get('Destination Port', 80))
            if status == "MALICIOUS":
                remote_ip = f"192.168.100.{random.randint(10,50)}"
                conn_status = "SYN_SENT"
            else:
                remote_ip = f"8.8.{random.randint(4,8)}.8"
                conn_status = "ESTABLISHED"
            
            record = {
                "time": time.strftime("%H:%M:%S"),
                "process": str(pid),
                "remote": f"{remote_ip}:{dst_port}",
                "risk": float(risk),
                "alert": status
            }
            # after determining pid and remote_ip
            self.proc_ip_map.setdefault(str(pid), set()).add(remote_ip)
            self.sim_buffer.append(record)
            if len(self.sim_buffer) > 2000: self.sim_buffer.pop(0)
            
            return {'score': float(risk), 'status': status, 'ip': remote_ip}
            
        except Exception as e:
            print(f"Net Inject Error: {e}")
            return None

    # ==========================================
    # 3. GETTERS
    # ==========================================
    def get_status(self):
        return {
            'live_data': list(self.live_buffer),
            'sim_data': self.sim_buffer
        }

    def get_network_stats(self):
        total_conns = len(self.live_buffer) + len(self.sim_buffer)
        
        # Use simulation risk if available, else 0
        max_risk = 0.0
        if self.sim_buffer:
            max_risk = max([c['risk'] for c in self.sim_buffer], default=0.0)

        return {
            'bytes_per_sec': self.bandwidth,
            'active_connections': total_conns,
            'unique_ips': len(self.live_ip_stats),
            'score': max_risk
        }

    # ==========================================
    # 3. UNIFIED GETTERS (The Magic Glue)
    # ==========================================
    def get_connection_details(self):
        """Merges Live and Sim data so the table is NEVER blank."""
        return self.live_connections + self.sim_connections
    
    def get_process_ip_map(self):
        return {
        pid: list(ips)
        for pid, ips in self.proc_ip_map.items()
    }

    def get_remote_ip_stats(self, limit=20):
        stats = []
        # Add Live IPs
        for ip, d in list(self.live_ip_stats.items())[:15]:
            stats.append({'ip': ip, 'conns': d['connections'], 'suspicious': False})
        # Add Sim IPs
        for c in self.sim_connections[-15:]:
            stats.append({'ip': c['remote_ip'], 'conns': 1, 'suspicious': c.get('risk', 0) > 0.5})
        return stats
# --- ADDED: Missing method for BackendManager/Settings ---
    def get_statistics(self):
        return {
            'bandwidth_usage': f"{self.bandwidth/1024:.2f} KB/s",
            'total_connections': len(self.live_buffer) + len(self.sim_buffer),
            'model_active': self.use_ml
        }

    # --- ADDED: Placeholder for Training ---
    def train_ml_model(self):
        return True, "Network training logic not implemented in this version."

    def get_connection_details(self):
        """Merges Live and Sim data."""
        return list(self.live_buffer) + self.sim_buffer
    
    def get_process_ip_map(self):
        return {pid: list(ips) for pid, ips in self.proc_ip_map.items()}

    def get_remote_ip_stats(self, limit=20):
        stats = []
        # Add Live IPs
        for ip, d in list(self.live_ip_stats.items())[:15]:
            stats.append({'ip': ip, 'conns': d['connections'], 'suspicious': False})
        # Add Sim IPs
        for c in self.sim_buffer[-15:]: # Fixed: used self.sim_buffer instead of undefined sim_connections
            # Check if dict has 'remote' key which contains ip:port
            if 'remote' in c:
                ip = c['remote'].split(':')[0]
                stats.append({'ip': ip, 'conns': 1, 'suspicious': c.get('risk', 0) > 0.5})
        return stats
    
    def block_ip(self, ip):
        return True, f"Blocked {ip} (Simulation)"