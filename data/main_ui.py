# main_ui.py
"""
Multi-page GUI for Three-Layer Malware Detector.
Unified Real-Time & Simulation Architecture.
"""

import os
import time
import threading
from tkinter import *
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
import pandas as pd
import random
import matplotlib
matplotlib.use("TkAgg") 
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

# Import backend modules
from backend_manager import BackendManager

# --- CONFIGURATION ---
# If this file exists, the system uses it for simulation.
# If not, it falls back to real hardware monitoring.
SIM_FILE_PATH = r"C:\Users\sasir\OneDrive\Documents\Project\demo\modified\Malware_Sim\Hybrid_malware.csv"

class MalwareDetectorUI:
    """Main application window with multi-page navigation"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Three-Layer Malware Detector")
        self.root.geometry("1200x800")
        
        # Initialize backend
        self.backend = BackendManager()
        try:
            self.backend.initialize_layers()
        except Exception as e:
            messagebox.showerror("Initialization Error", f"Failed to initialize backend: {e}")
            return
        
        # Monitoring state
        self.monitoring_active = False
        self.update_job = None
        
        # Create main layout
        self.create_navigation()
        self.create_pages()
        
        # Show dashboard by default
        self.show_page("dashboard")
    
    def create_navigation(self):
        """Create top navigation bar"""
        nav_frame = Frame(self.root, bg="#2c3e50", height=60)
        nav_frame.pack(side=TOP, fill=X)
        nav_frame.pack_propagate(False)
        
        # Title
        title = Label(nav_frame, text="🛡️ Malware Detector", 
                     bg="#2c3e50", fg="white", 
                     font=("Arial", 18, "bold"))
        title.pack(side=LEFT, padx=20, pady=10)
        
        # Navigation buttons (Left Side)
        btn_style = {
            'bg': "#34495e",
            'fg': "white",
            'activebackground': "#1abc9c",
            'activeforeground': "white",
            'bd': 0,
            'padx': 20,
            'pady': 10,
            'font': ("Arial", 11)
        }
        
        Button(nav_frame, text="Dashboard", 
               command=lambda: self.show_page("dashboard"), **btn_style).pack(side=LEFT, padx=2)
        
        Button(nav_frame, text="Static Layer", 
               command=lambda: self.show_page("static"), **btn_style).pack(side=LEFT, padx=2)
        
        Button(nav_frame, text="Dynamic Layer", 
               command=lambda: self.show_page("dynamic"), **btn_style).pack(side=LEFT, padx=2)
        
        Button(nav_frame, text="Network Layer", 
               command=lambda: self.show_page("network"), **btn_style).pack(side=LEFT, padx=2)
        
        Button(nav_frame, text="Alerts & Logs", 
               command=lambda: self.show_page("alerts"), **btn_style).pack(side=LEFT, padx=2)
        
        Button(nav_frame, text="⚙ Settings", 
               command=lambda: self.show_page("settings"), **btn_style).pack(side=LEFT, padx=2)
        
        # --- UNIFIED CONTROL ---
        # Single "Start System" button that handles both Real and Sim modes
        self.stop_btn = Button(nav_frame, text="⏹ Stop System", 
                              command=self.stop_monitoring,
                              bg="#e74c3c", fg="white", bd=0, padx=15, pady=8,
                              state=DISABLED)
        self.stop_btn.pack(side=RIGHT, padx=5)

        self.start_btn = Button(nav_frame, text="▶ Start Real-Time System", 
                               command=self.start_smart_monitoring,
                               bg="#27ae60", fg="white", bd=0, padx=15, pady=8)
        self.start_btn.pack(side=RIGHT, padx=5)
    
    def create_pages(self):
        """Create container for all pages"""
        self.pages_container = Frame(self.root, bg="white")
        self.pages_container.pack(fill=BOTH, expand=True)
        self.pages = {}
        
        self.pages['dashboard'] = self.create_dashboard_page()
        self.pages['static'] = self.create_static_page()
        self.pages['dynamic'] = self.create_dynamic_page()
        self.pages['network'] = self.create_network_page()
        self.pages['alerts'] = self.create_alerts_page()
        self.pages['settings'] = self.create_settings_page()
    
    def show_page(self, page_name):
        for name, page in self.pages.items():
            if name == page_name:
                page.pack(fill=BOTH, expand=True)
            else:
                page.pack_forget()
    
    # ==================== PAGE CREATION ====================

    def create_dashboard_page(self):
        page = Frame(self.pages_container, bg="white")
        # Header
        header = Frame(page, bg="#ecf0f1", height=80)
        header.pack(fill=X)
        header.pack_propagate(False)
        Label(header, text="Dashboard Overview", font=("Arial", 20, "bold"), bg="#ecf0f1").pack(anchor=W, padx=20, pady=20)
        
        # Stats Cards
        content = Frame(page, bg="white")
        content.pack(fill=BOTH, expand=True, padx=20, pady=20)
        scores_frame = Frame(content, bg="white")
        scores_frame.pack(fill=X, pady=(0, 20))
        self.dash_static_score = self.create_score_card(scores_frame, "Static Score", "0.00", "#3498db")
        self.dash_dynamic_score = self.create_score_card(scores_frame, "Dynamic Score", "0.00", "#e67e22")
        self.dash_network_score = self.create_score_card(scores_frame, "Network Score", "0.00", "#9b59b6")
        self.dash_ensemble_score = self.create_score_card(scores_frame, "Ensemble", "0.00", "#27ae60")
        
        # Status
        status_frame = LabelFrame(content, text="Current Status", font=("Arial", 12, "bold"), bg="white", padx=20, pady=10)
        status_frame.pack(fill=X, pady=(0, 20))
        self.status_label = Label(status_frame, text="Status: Idle", font=("Arial", 14), bg="white", fg="#2c3e50")
        self.status_label.pack(anchor=W, pady=5)
        self.ensemble_label = Label(status_frame, text="Verdict: Unknown", font=("Arial", 12), bg="white")
        self.ensemble_label.pack(anchor=W, pady=5)
        
        # Quick Stats Tree
        stats_frame = LabelFrame(content, text="Statistics", font=("Arial", 12, "bold"), bg="white")
        stats_frame.pack(fill=BOTH, expand=True)
        self.stats_tree = ttk.Treeview(stats_frame, columns=("value",), height=10)
        self.stats_tree.heading("#0", text="Metric")
        self.stats_tree.heading("value", text="Value")
        self.stats_tree.column("#0", width=400)
        self.stats_tree.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Recent Alerts
        alerts_preview = LabelFrame(content, text="Recent Alerts", font=("Arial", 12, "bold"), bg="white")
        alerts_preview.pack(fill=X, pady=(20, 0))
        self.dash_alerts_tree = ttk.Treeview(alerts_preview, columns=("time", "label", "score"), height=5)
        self.dash_alerts_tree.heading("#0", text="")
        self.dash_alerts_tree.heading("time", text="Time")
        self.dash_alerts_tree.heading("label", text="Label")
        self.dash_alerts_tree.heading("score", text="Score")
        self.dash_alerts_tree.column("#0", width=0, stretch=False)
        self.dash_alerts_tree.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        return page

    def create_score_card(self, parent, title, value, color):
        card = Frame(parent, bg=color, relief=RAISED, bd=2)
        card.pack(side=LEFT, fill=BOTH, expand=True, padx=10)
        Label(card, text=title, bg=color, fg="white", font=("Arial", 12)).pack(pady=(15, 5))
        value_label = Label(card, text=value, bg=color, fg="white", font=("Arial", 24, "bold"))
        value_label.pack(pady=(0, 15))
        return value_label

    def create_static_page(self):
        page = Frame(self.pages_container, bg="white")
        header = Frame(page, bg="#3498db", height=80)
        header.pack(fill=X)
        header.pack_propagate(False)
        Label(header, text="Static File Analysis", font=("Arial", 20, "bold"), bg="#3498db", fg="white").pack(anchor=W, padx=20, pady=20)
        
        controls = Frame(page, bg="white")
        controls.pack(fill=X, padx=20, pady=10)
        Label(controls, text="File Path:", bg="white").pack(side=LEFT)
        self.static_path_var = StringVar()
        Entry(controls, textvariable=self.static_path_var, width=60).pack(side=LEFT, padx=10)
        Button(controls, text="Browse", command=self.browse_file).pack(side=LEFT)
        Button(controls, text="Scan File", command=self.scan_static_file, bg="#3498db", fg="white").pack(side=LEFT, padx=5)
        Button(controls, text="Quarantine", command=self.quarantine_file, bg="#e74c3c", fg="white").pack(side=LEFT)
        
        results = Frame(page, bg="white")
        results.pack(fill=BOTH, expand=True, padx=20, pady=10)
        left_frame = LabelFrame(results, text="File Details", font=("Arial", 11, "bold"))
        left_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 10))
        self.static_details_tree = ttk.Treeview(left_frame, columns=("value",), height=15)
        self.static_details_tree.heading("#0", text="Property")
        self.static_details_tree.heading("value", text="Value")
        self.static_details_tree.column("#0", width=200)
        self.static_details_tree.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        right_frame = LabelFrame(results, text="Scan History", font=("Arial", 11, "bold"))
        right_frame.pack(side=RIGHT, fill=BOTH, expand=True)
        self.static_history_tree = ttk.Treeview(right_frame, columns=("file", "score", "label"), height=15)
        self.static_history_tree.heading("#0", text="")
        self.static_history_tree.heading("file", text="File")
        self.static_history_tree.heading("score", text="Score")
        self.static_history_tree.heading("label", text="Label")
        self.static_history_tree.column("#0", width=0)
        self.static_history_tree.pack(fill=BOTH, expand=True, padx=5, pady=5)
        return page

    # ==================== DYNAMIC PAGE ====================
    def create_dynamic_page(self):
        page = Frame(self.pages_container, bg="#ecf0f1")
        header = Frame(page, bg="#ecf0f1")
        header.pack(fill=X, pady=(0, 20))
        Label(header, text="Dynamic Analysis", font=("Segoe UI", 24, "bold"), bg="#ecf0f1", fg="#2c3e50").pack(side=LEFT, padx=20, pady=10)

        # Tabs
        self.dyn_tabs = ttk.Notebook(page)
        self.dyn_tabs.pack(fill=BOTH, expand=True, padx=20, pady=10)
        self.tab_live = Frame(self.dyn_tabs, bg="white")
        self.tab_csv = Frame(self.dyn_tabs, bg="white")
        self.dyn_tabs.add(self.tab_live, text="  Live Monitor (Raw Features)  ")
        self.dyn_tabs.add(self.tab_csv, text="  Analysis (ML Prediction)  ")
        
        # --- TAB 1: LIVE MONITOR ---
        live_table_frame = Frame(self.tab_live)
        live_table_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Status Label inside the tab
        self.lbl_dyn_status = Label(live_table_frame, text="Status: Idle", font=("Segoe UI", 11), bg="white", fg="#7f8c8d")
        self.lbl_dyn_status.pack(anchor=W, pady=5)

        feat_cols = ['nproc', 'nppid', 'avg_thr', 'n64', 'avg_hndl', 'ndlls', 'avg_dll', 'nhandles', 'avg_h_proc', 'nsvc', 'k_drv', 'fs_drv', 'proc_svc', 'sh_svc', 'int_svc', 'nactive']
        columns_live = ["time", "pid", "name"] + feat_cols
        
        self.tree_live = ttk.Treeview(live_table_frame, columns=columns_live, show="headings", height=15)
        self.tree_live.heading("time", text="Time")
        self.tree_live.column("time", width=80, minwidth=80)
        self.tree_live.heading("pid", text="PID")
        self.tree_live.column("pid", width=60, minwidth=60)
        self.tree_live.heading("name", text="Process Name")
        self.tree_live.column("name", width=150, minwidth=150)
        for col in feat_cols:
            self.tree_live.heading(col, text=col)
            self.tree_live.column(col, width=60, minwidth=50, anchor=CENTER)

        vsb = ttk.Scrollbar(live_table_frame, orient="vertical", command=self.tree_live.yview)
        hsb = ttk.Scrollbar(live_table_frame, orient="horizontal", command=self.tree_live.xview)
        self.tree_live.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree_live.pack(side=LEFT, fill=BOTH, expand=True)
        vsb.pack(side=RIGHT, fill=Y)
        hsb.pack(side=BOTTOM, fill=X)

        # --- TAB 2: CSV ANALYSIS ---
        self.lbl_csv_info = Label(self.tab_csv, text="Waiting for system start...", font=("Segoe UI", 10), bg="white", fg="gray")
        self.lbl_csv_info.pack(pady=10)
        
        columns_csv = ("pid", "name", "risk", "status")
        self.tree_csv = ttk.Treeview(self.tab_csv, columns=columns_csv, show="headings", height=15)
        self.tree_csv.heading("pid", text="PID")
        self.tree_csv.heading("name", text="Malware Family / Name")
        self.tree_csv.heading("risk", text="Risk Score")
        self.tree_csv.heading("status", text="Status")
        self.tree_csv.column("pid", width=80, anchor=CENTER)
        self.tree_csv.column("name", width=300)
        self.tree_csv.column("risk", width=100, anchor=CENTER)
        self.tree_csv.column("status", width=100, anchor=CENTER)
        
        scroll_csv = ttk.Scrollbar(self.tab_csv, orient=VERTICAL, command=self.tree_csv.yview)
        self.tree_csv.configure(yscroll=scroll_csv.set)
        
        self.tree_csv.pack(side=LEFT, fill=BOTH, expand=True, padx=(10,0), pady=10)
        scroll_csv.pack(side=RIGHT, fill=Y, pady=10)
        
        self.tree_csv.tag_configure("malicious", background="#ffcccc")
        self.tree_csv.tag_configure("safe", background="#ffffff")

        return page

    # ==================== NETWORK PAGE ====================
    def create_network_page(self):
        page = Frame(self.pages_container, bg="#ecf0f1")
        
        # Header
        header = Frame(page, bg="#9b59b6")
        header.pack(fill=X, pady=(0, 20))
        Label(header, text="Network Traffic Analysis", font=("Segoe UI", 24, "bold"), bg="#9b59b6", fg="white").pack(side=LEFT, padx=20, pady=10)
        
        # --- STATS ROW ---
        stats_frame = Frame(page, bg="#ecf0f1")
        stats_frame.pack(fill=X, padx=20, pady=(0, 10))
        
        self.net_bps_label = Label(stats_frame, text="Bandwidth: 0 KB/s", font=("Segoe UI", 12, "bold"), bg="#ecf0f1", fg="#2c3e50")
        self.net_bps_label.pack(side=LEFT, padx=20)
        
        self.net_conns_label = Label(stats_frame, text="Active Conns: 0", font=("Segoe UI", 12, "bold"), bg="#ecf0f1", fg="#2c3e50")
        self.net_conns_label.pack(side=LEFT, padx=20)
        
        self.net_ips_label = Label(stats_frame, text="Unique IPs: 0", font=("Segoe UI", 12, "bold"), bg="#ecf0f1", fg="#2c3e50")
        self.net_ips_label.pack(side=LEFT, padx=20)
        
        # --- TABS ---
        self.net_tabs = ttk.Notebook(page)
        self.net_tabs.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        self.tab_net_live = Frame(self.net_tabs, bg="white")
        self.tab_net_sim = Frame(self.net_tabs, bg="white")
        
        self.net_tabs.add(self.tab_net_live, text="  Live Traffic (Raw)  ")
        self.net_tabs.add(self.tab_net_sim, text="  Threat Detection (ML)  ")
        
        # --- TAB 1: LIVE TRAFFIC ---
        cols_live = ("time", "local", "remote", "status", "pid")
        self.tree_net_live = ttk.Treeview(self.tab_net_live, columns=cols_live, show="headings", height=15)
        
        self.tree_net_live.heading("time", text="Time")
        self.tree_net_live.heading("local", text="Local Addr")
        self.tree_net_live.heading("remote", text="Remote Addr")
        self.tree_net_live.heading("status", text="Status")
        self.tree_net_live.heading("pid", text="PID")
        
        self.tree_net_live.column("time", width=100)
        self.tree_net_live.column("local", width=150)
        self.tree_net_live.column("remote", width=150)
        self.tree_net_live.column("status", width=100)
        self.tree_net_live.column("pid", width=80)
        
        scroll_live = ttk.Scrollbar(self.tab_net_live, orient=VERTICAL, command=self.tree_net_live.yview)
        self.tree_net_live.configure(yscroll=scroll_live.set)
        self.tree_net_live.pack(side=LEFT, fill=BOTH, expand=True)
        scroll_live.pack(side=RIGHT, fill=Y)

        # --- TAB 2: THREAT DETECTION ---
        cols_sim = ("time", "process", "remote", "risk", "status")
        self.tree_net_sim = ttk.Treeview(self.tab_net_sim, columns=cols_sim, show="headings", height=15)
        
        self.tree_net_sim.heading("time", text="Time")
        self.tree_net_sim.heading("process", text="Process PID")
        self.tree_net_sim.heading("remote", text="Remote Destination")
        self.tree_net_sim.heading("risk", text="Risk Score")
        self.tree_net_sim.heading("status", text="Detection")
        
        self.tree_net_sim.column("time", width=100)
        self.tree_net_sim.column("process", width=100)
        self.tree_net_sim.column("remote", width=200)
        self.tree_net_sim.column("risk", width=100)
        self.tree_net_sim.column("status", width=120)
        
        scroll_sim = ttk.Scrollbar(self.tab_net_sim, orient=VERTICAL, command=self.tree_net_sim.yview)
        self.tree_net_sim.configure(yscroll=scroll_sim.set)
        self.tree_net_sim.pack(side=LEFT, fill=BOTH, expand=True)
        scroll_sim.pack(side=RIGHT, fill=Y)
        
        self.tree_net_sim.tag_configure("malicious", background="#ffcccc")
        self.tree_net_sim.tag_configure("safe", background="#ffffff")
        
        return page

    def update_network_view(self):
        """Updates both network tabs"""
        if not self.backend: return
        if not hasattr(self, 'tree_net_live'): return

        try:
            # Fetch Data
            status_data = self.backend.network_layer.get_status()
            stats = self.backend.network_layer.get_network_stats()
            
            live_count = len(status_data['live_data'])
            
            # --- 1. UPDATE LABELS ---
            bps = stats.get('bytes_per_sec', 0)
            if hasattr(self, 'net_bps_label'):
                self.net_bps_label.config(text=f"Bandwidth: {bps/1024:.1f} KB/s")
            if hasattr(self, 'net_conns_label'):
                self.net_conns_label.config(text=f"Active Conns: {live_count}")
            
            # --- 2. UPDATE LIVE TABLE ---
            for item in self.tree_net_live.get_children(): 
                self.tree_net_live.delete(item)
                
            # Show last 50 items (Reversed for newest first)
            for row in list(status_data['live_data'])[-50:][::-1]:
                self.tree_net_live.insert("", "end", values=(
                    row.get('time', ''), 
                    row.get('local', ''), 
                    row.get('remote', ''), 
                    row.get('status', ''), 
                    row.get('pid', '')
                ))
                
            # --- 3. UPDATE SIMULATION TABLE ---
            for item in self.tree_net_sim.get_children(): 
                self.tree_net_sim.delete(item)
                
            for row in list(status_data['sim_data'])[-50:][::-1]:
                tag = "malicious" if row.get('alert') == "MALICIOUS" else "safe"
                self.tree_net_sim.insert("", "end", values=(
                    row.get('time', ''), 
                    row.get('process', ''), 
                    row.get('remote', ''), 
                    f"{row.get('risk', 0):.4f}", 
                    row.get('alert', '')
                ), tags=(tag,))
                
        except Exception as e:
            print(f"[Net UI Update Error] {e}")

    # ==================== ALERTS PAGE (FIXED VISUALIZATION) ====================
    def create_alerts_page(self):
        page = Frame(self.pages_container, bg="white")
        header = Frame(page, bg="#e74c3c", height=80)
        header.pack(fill=X)
        header.pack_propagate(False)
        Label(header, text="Threat Intelligence & Forensics", font=("Segoe UI", 24, "bold"), bg="#e74c3c", fg="white").pack(side=LEFT, padx=20, pady=20)
        
        # Controls
        controls = Frame(page, bg="white")
        controls.pack(fill=X, padx=20, pady=10)
        Button(controls, text="🗑 Clear All Alerts", command=self.clear_alerts, 
               bg="#95a5a6", fg="white", font=("Arial", 10, "bold"), padx=15, pady=5).pack(side=LEFT)
        Button(controls, text="💾 Export Logs", command=self.export_logs, 
               bg="#3498db", fg="white", font=("Arial", 10, "bold"), padx=15, pady=5).pack(side=LEFT, padx=10)
        Button(controls, text="🔄 Refresh Graph", command=self.update_alert_visualization, 
               bg="#27ae60", fg="white", font=("Arial", 10, "bold"), padx=15, pady=5).pack(side=LEFT)
        
        # Tabs
        self.alert_tabs = ttk.Notebook(page)
        self.alert_tabs.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        self.tab_alert_vis = Frame(self.alert_tabs, bg="white")
        self.tab_alert_list = Frame(self.alert_tabs, bg="white")
        
        self.alert_tabs.add(self.tab_alert_vis, text="  Live Attack Graph (Visualization)  ")
        self.alert_tabs.add(self.tab_alert_list, text="  Alert Logs (Table)  ")
        
        # --- TAB 1: VISUALIZATION (MATPLOTLIB) ---
        vis_controls = Frame(self.tab_alert_vis, bg="white")
        vis_controls.pack(fill=X, padx=10, pady=5)
        Label(
            vis_controls,
            text="Visual Forensics: Process-to-Network Correlation",
            bg="white",
            font=("Arial", 12, "bold")
        ).pack(side=LEFT)

        # FIXED: Create canvas with correct variable names
        self.alert_fig, self.alert_ax = plt.subplots(figsize=(10, 6), dpi=100)
        self.alert_fig.patch.set_facecolor('white')
        self.alert_ax.axis('off')

        self.alert_canvas = FigureCanvasTkAgg(self.alert_fig, master=self.tab_alert_vis)
        self.alert_canvas.get_tk_widget().pack(fill=BOTH, expand=True, padx=10, pady=10)

        # --- TAB 2: LIST VIEW ---
        cols = ("time", "label", "confidence", "reason")
        self.alerts_tree = ttk.Treeview(self.tab_alert_list, columns=cols, show="headings", height=15)
        self.alerts_tree.heading("time", text="Timestamp")
        self.alerts_tree.heading("label", text="Threat Type")
        self.alerts_tree.heading("confidence", text="Risk Score")
        self.alerts_tree.heading("reason", text="Detailed Analysis")
        self.alerts_tree.column("time", width=120)
        self.alerts_tree.column("label", width=150)
        self.alerts_tree.column("confidence", width=80, anchor=CENTER)
        self.alerts_tree.column("reason", width=500)
        self.alerts_tree.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        return page

    def create_settings_page(self):
        page = Frame(self.pages_container, bg="white")
        header = Frame(page, bg="#34495e", height=80)
        header.pack(fill=X)
        header.pack_propagate(False)
        Label(header, text="Settings & ML Model Training", font=("Arial", 20, "bold"), bg="#34495e", fg="white").pack(anchor=W, padx=20, pady=20)
        
        ml_frame = LabelFrame(page, text="Machine Learning Status", font=("Arial", 12, "bold"), bg="white", padx=20, pady=20)
        ml_frame.pack(fill=X, padx=20, pady=20)
        status_text = Text(ml_frame, height=6, bg="#ecf0f1", wrap=WORD)
        status_text.pack(fill=X, pady=10)
        ml_status = self.backend.get_ml_status()
        status_lines = [
            "ML Model Status:",
            f"  • Static Layer: {'✓ ENABLED' if ml_status['static'] else '✗ DISABLED'}",
            f"  • Dynamic Layer: {'✓ ENABLED' if ml_status['dynamic'] else '✗ DISABLED'}",
            f"  • Network Layer: {'✓ ENABLED' if ml_status['network'] else '✗ DISABLED'}",
        ]
        status_text.insert("1.0", "\n".join(status_lines))
        
        train_frame = LabelFrame(page, text="Train ML Models", font=("Arial", 12, "bold"), bg="white", padx=20, pady=20)
        train_frame.pack(fill=X, padx=20, pady=(0, 20))
        Button(train_frame, text="🔧 Train All Models", command=self.train_ml_models, bg="#3498db", fg="white", font=("Arial", 11, "bold"), padx=20, pady=10).pack(anchor=W)
        self.train_status_label = Label(train_frame, text="", bg="white", fg="#27ae60")
        self.train_status_label.pack(anchor=W, pady=(10, 0))
        
        # Log viewer
        log_frame = LabelFrame(page, text="System Logs", font=("Arial", 12, "bold"), bg="white", padx=20, pady=20)
        log_frame.pack(fill=BOTH, expand=True, padx=20, pady=(0, 20))
        self.log_text = Text(log_frame, height=10, bg="#2c3e50", fg="#ecf0f1", wrap=WORD, font=("Consolas", 9))
        self.log_text.pack(fill=BOTH, expand=True)
        
        return page

    # ==================== SMART MONITORING LOGIC ====================
    def start_smart_monitoring(self):
        """
        Starts Real-Time Monitoring + Optional Simulation.
        """
        # 1. ALWAYS START REAL-TIME BACKEND
        self.backend.start_monitoring()
        self.monitoring_active = True
        
        # UI Updates
        self.start_btn.config(state=DISABLED, text="System Running")
        self.stop_btn.config(state=NORMAL)
        
        # 2. CHECK FOR CSV FILE
        if os.path.exists(SIM_FILE_PATH):
            self.status_label.config(text="Status: Hybrid Mode (Live + CSV)", fg="#8e44ad")
            self.log_message(f"Found CSV. Starting Hybrid Injection...")
            self.run_simulation_thread(SIM_FILE_PATH)
        else:
            self.status_label.config(text="Status: Real-Time Only", fg="#27ae60")
            self.log_message("No CSV found. Running Real-Time Hardware Monitor.")
        
        # 3. START UI REFRESH
        if self.update_job is None:
            self.schedule_updates()

    def stop_monitoring(self):
        """Stops whatever mode is running"""
        self.backend.stop_monitoring()
        self.monitoring_active = False
        
        self.start_btn.config(state=NORMAL, text="▶ Start Real-Time System")
        self.stop_btn.config(state=DISABLED)
        self.status_label.config(text="Status: System Stopped", fg="#e74c3c")
        self.log_message("System stopped.")

    # ==================== UI UPDATE LOOP ====================
    def schedule_updates(self):
        """Schedule periodic UI updates"""
        if not self.monitoring_active:
            self.update_job = None
            return
            
        try:
            self.update_dashboard()
            self.update_dynamic_view()
            self.update_network_view()
            self.update_alerts_view()
        except Exception as e:
            print(f"Update error: {e}")
        
        self.update_job = self.root.after(1000, self.schedule_updates)

    def update_dashboard(self):
        """Update dashboard view"""
        try:
            stats = self.backend.get_statistics()
            
            # Update stats tree
            for item in self.stats_tree.get_children():
                self.stats_tree.delete(item)
            
            self.stats_tree.insert("", END, text="Total Detections", values=(stats.get('total_detections', 0),))
            self.stats_tree.insert("", END, text="Total Alerts", values=(stats.get('total_alerts', 0),))
            self.stats_tree.insert("", END, text="Monitoring Active", values=("Yes" if stats.get('monitoring_active') else "No",))
            
            # Update alert preview
            for item in self.dash_alerts_tree.get_children(): 
                self.dash_alerts_tree.delete(item)
            for alert in self.backend.alerts[-5:]:
                self.dash_alerts_tree.insert("", END, values=(
                    alert['timestamp'], alert['label'], f"{alert['confidence']:.2f}"
                ))
                
        except Exception as e:
            print(f"Dash update: {e}")

    def update_dynamic_view(self):
        """Update dynamic layer view"""
        try:
            status = self.backend.dynamic_layer.get_status()
            
            # 1. Update Live Table (Tab 1)
            if hasattr(self, 'tree_live'):
                for item in self.tree_live.get_children(): 
                    self.tree_live.delete(item)
                for row in reversed(status['realtime_data'][-50:]):
                    self.tree_live.insert("", "end", values=(
                        row['timestamp'], row['pid'], row['name'], 
                        row.get('status', 'N/A'), row.get('cpu', '0%'), row.get('memory', '0%')
                    ))
            
            # 2. Update Simulation Table (Tab 2)
            if hasattr(self, 'tree_csv'):
                for item in self.tree_csv.get_children(): 
                    self.tree_csv.delete(item)
                for row in status['csv_data'][-50:]:
                    tag = "malicious" if row['status'] == "MALICIOUS" else "safe"
                    self.tree_csv.insert("", "end", values=(
                        row['pid'], row['name'], f"{row['risk_score']:.4f}", row['status']
                    ), tags=(tag,))
                    
        except Exception as e:
            print(f"Dyn update: {e}")

    def update_alerts_view(self):
        """FIXED: Update both alert table and visualization"""
        # 1. Update Table
        if hasattr(self, 'alerts_tree'):
            for item in self.alerts_tree.get_children(): 
                self.alerts_tree.delete(item)
            for alert in self.backend.alerts:
                self.alerts_tree.insert("", 0, values=(
                    alert['timestamp'], alert['label'], 
                    f"{alert['confidence']:.2f}", alert['reason']
                ))
        
        # 2. Update Graph - FIXED: Now actually calls the visualization
        self.update_alert_visualization()

    def update_alert_visualization(self):
        """FIXED: Draw the attack graph visualization"""
        if not hasattr(self, 'alert_ax') or not hasattr(self, 'alert_canvas'):
            print("[WARN] Alert visualization not initialized")
            return

        try:
            self.alert_ax.clear()
            self.alert_ax.axis('off')
            
            alerts = self.backend.get_alerts()[:6]  # Show top 6 most recent threats
            
            if not alerts:
                self.alert_ax.text(0.5, 0.5, "System Secure: No Active Threats", 
                            ha='center', va='center', fontsize=20, 
                            color='#27ae60', alpha=0.6)
                self.alert_canvas.draw()
                return

            # Layout Settings
            left_x = 0.1   # Process Node X
            right_x = 0.9  # IP Node X
            start_y = 0.9
            gap_y = 0.15
            
            # Draw Column Labels
            self.alert_ax.text(left_x, 1.0, "INFECTED PROCESSES", 
                              ha='center', fontsize=12, fontweight='bold', color='#c0392b')
            self.alert_ax.text(right_x, 1.0, "DESTINATION (C2)", 
                              ha='center', fontsize=12, fontweight='bold', color='#f39c12')
            
            for i, alert in enumerate(alerts):
                y = start_y - (i * gap_y)
                
                # Extract Data (FIXED: uses correct field names)
                pid = alert.get('pid', '???')
                proc = alert.get('process', 'Unknown')
                ip = alert.get('ip', 'Unknown IP')
                risk = alert.get('confidence', 0.0)
                
                # 1. Draw Process Node (Left)
                self.alert_ax.plot(left_x, y, marker='o', markersize=20, color='#e74c3c')
                self.alert_ax.text(left_x, y + 0.04, f"{proc}\n(PID: {pid})", 
                                  ha='center', fontsize=10, fontweight='bold')
                
                # 2. Draw IP Node (Right)
                self.alert_ax.plot(right_x, y, marker='s', markersize=20, color='#f39c12')
                self.alert_ax.text(right_x, y + 0.04, f"C2 Server\n{ip}", 
                                  ha='center', fontsize=10, fontweight='bold')
                
                # 3. Draw Connecting Line
                line_color = plt.cm.Reds(risk) 
                self.alert_ax.plot([left_x+0.05, right_x-0.05], [y, y], 
                                  color=line_color, linewidth=3, linestyle='-')
                
                # 4. Annotate the Line
                self.alert_ax.text(0.5, y + 0.01, f"Data Exfiltration (Risk: {risk:.2f})", 
                                  ha='center', fontsize=9, color='red', 
                                  backgroundcolor='white')

            self.alert_canvas.draw()

        except Exception as e:
            print(f"[Alert Viz Error] {e}")
            import traceback
            traceback.print_exc()

    # ==================== SIMULATION THREAD ====================
    def run_simulation_thread(self, file_path):
        def sim_loop():
            try:
                df = pd.read_csv(file_path)
                df.columns = df.columns.str.strip()
                
                # Reset
                self.backend.dynamic_layer.csv_buffer = []
                self.backend.network_layer.sim_buffer = []
                self.backend.alerts = []
                
                self.lbl_csv_info.config(text=f"Streaming: {os.path.basename(file_path)}", fg="#8e44ad")
                
                for index, row in df.iterrows():
                    if not self.monitoring_active: 
                        break
                    
                    sim_pid = random.randint(1000, 9999)
                    cat_name = row.get('Category', 'Unknown')
                    
                    # Feed Layers
                    dyn_result = self.backend.dynamic_layer.inject_single_row(row, sim_pid, cat_name)
                    net_result = self.backend.network_layer.inject_single_row(row, sim_pid)
                    
                    # CORRELATION
                    if dyn_result and net_result:
                        is_proc_mal = dyn_result['status'] == "MALICIOUS"
                        is_net_mal = net_result['status'] == "MALICIOUS"
                        
                        if is_proc_mal and is_net_mal:
                            alert = {
                                'timestamp': datetime.now().strftime("%H:%M:%S"),
                                'label': "DATA EXFILTRATION",
                                'confidence': (dyn_result['score'] + net_result['score']) / 2,
                                'reason': f"Spyware '{cat_name}' (PID {sim_pid}) sending data to {net_result['ip']}",
                                # RAW DATA FOR VISUALIZATION
                                'pid': str(sim_pid),
                                'process': cat_name,
                                'ip': net_result['ip']
                            }
                            self.backend.alerts.insert(0, alert)
                    
                    time.sleep(0.5)
                
                if self.monitoring_active:
                    self.lbl_csv_info.config(text="Feed Finished.", fg="gray")
                    
            except Exception as e:
                print(f"Sim Loop Error: {e}")
        
        threading.Thread(target=sim_loop, daemon=True).start()

    # ==================== UTILITY FUNCTIONS ====================
    def browse_file(self):
        path = filedialog.askopenfilename()
        if path: 
            self.static_path_var.set(path)

    def scan_static_file(self):
        path = self.static_path_var.get().strip()
        if not path:
            messagebox.showwarning("No File", "Please select a file first")
            return
        
        try:
            result = self.backend.scan_static(path)
            for item in self.static_details_tree.get_children():
                self.static_details_tree.delete(item)
            for key, value in result.details.items():
                self.static_details_tree.insert("", END, text=key, values=(str(value),))
            self.update_static_history()
            self.log_message(f"Static scan completed: {path} - Score: {result.score} ({result.label})")
            if result.label == "Malicious":
                messagebox.showwarning("Malicious File Detected", 
                                      f"Score: {result.score}\nRecommendation: Quarantine this file")
        except Exception as e:
            messagebox.showerror("Scan Error", str(e))

    def update_static_history(self):
        for item in self.static_history_tree.get_children():
            self.static_history_tree.delete(item)
        history = self.backend.static_layer.get_scan_history(20)
        for scan in history:
            filename = os.path.basename(scan['details']['path'])
            self.static_history_tree.insert("", END, values=(filename, scan['score'], scan['label']))

    def quarantine_file(self):
        path = self.static_path_var.get().strip()
        if not path:
            messagebox.showwarning("No File", "Please scan a file first")
            return
        success, message = self.backend.quarantine_file(path)
        if success:
            self.log_message(f"Quarantined: {path}")
            messagebox.showinfo("Success", message)
            self.static_path_var.set("")
        else:
            messagebox.showerror("Failed", message)

    def clear_alerts(self): 
        """Clear all alerts and refresh visualization"""
        self.backend.alerts.clear()
        self.update_alerts_view()
        self.update_alert_visualization()
        self.log_message("Alerts cleared")

    def export_logs(self):
        """Export logs to CSV"""
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV files", "*.csv")])
        if path:
            success, message = self.backend.export_logs(path)
            if success:
                self.log_message(f"Exported logs to {path}")
                messagebox.showinfo("Success", message)
            else:
                messagebox.showerror("Failed", message)

    def block_ip(self):
        selection = self.remote_ips_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an IP")
            return
        ip = self.remote_ips_tree.item(selection[0])['text']
        if messagebox.askyesno("Confirm", f"Block IP {ip}?"):
            success, message = self.backend.block_ip(ip)
            if success:
                self.log_message(f"Blocked IP: {ip}")
                messagebox.showinfo("Success", message)
            else:
                cmd = self.backend.network_layer.get_block_command(ip)
                messagebox.showinfo("Manual Block Required", 
                                   f"{message}\n\nRun this command manually:\n{cmd}")

    def log_message(self, message):
        """Log message to console and UI"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        if hasattr(self, 'log_text'):
            self.log_text.insert(END, log_entry)
            self.log_text.see(END)
        print(log_entry.strip())

    def train_ml_models(self):
        """Train ML models"""
        self.train_status_label.config(text="Training... This may take a minute.", fg="#f39c12")
        self.root.update()
        
        def train_thread():
            results = self.backend.train_all_ml_models()
            success_count = sum(1 for success, _ in results.values() if success)
            
            if success_count == 3:
                message = "✓ All models trained successfully!"
                color = "#27ae60"
            elif success_count > 0:
                message = f"⚠ {success_count}/3 models trained. Check console for errors."
                color = "#f39c12"
            else:
                message = "✗ Training failed. Check console for errors."
                color = "#e74c3c"
            
            self.root.after(0, lambda: self.train_status_label.config(text=message, fg=color))
            self.root.after(0, lambda: self.log_message(f"ML Training: {message}"))
            
            details = []
            for layer, (success, msg) in results.items():
                status = "✓" if success else "✗"
                details.append(f"{status} {layer.capitalize()}: {msg}")
            
            self.root.after(0, lambda: messagebox.showinfo("Training Results", "\n".join(details)))
        
        threading.Thread(target=train_thread, daemon=True).start()

# ==================== MAIN ====================
def main():
    root = Tk()
    app = MalwareDetectorUI(root)
    
    def on_closing():
        app.stop_monitoring()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()