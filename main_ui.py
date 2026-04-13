"""
------------------------------------------------------------------------------
 Project: Detection and elimination of stealthy malware variants using deep learning algorithms 
 File : Main_ui
 Author:  Sasirudh Ponneri Balaji & Sairahul S
 Date:    April 2026
 
 Copyright (c) 2026 Sasirudh Ponneri Balaji. All rights reserved.
 
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
from resource_manager import get_resource_path

# Import backend modules
from backend_manager import BackendManager

# ==================== CYBERSECURITY THEME ====================
class CyberTheme:
    """Professional Cybersecurity Color Palette"""
    # Backgrounds
    BG_DARK = '#0a0e27'
    BG_PANEL = '#1a1d2e'
    BG_CARD = "#252b48" #252b48
    BG_HOVER = '#2d3561'
    
    # Accents
    ACCENT_CYAN = '#00d9ff'
    ACCENT_GREEN = '#00ff88'
    ACCENT_RED = '#ff2e63'
    ACCENT_YELLOW = '#ffd93d'
    ACCENT_PURPLE = '#a855f7'
    
    # Text
    TEXT_PRIMARY = '#e8eaf6'
    TEXT_SECONDARY = '#9ca3af'  
    TEXT_DIM = '#6b7280'   
    
    # Status Colors
    STATUS_SAFE = '#00ff88'
    STATUS_WARNING = '#ffd93d'
    STATUS_DANGER = '#ff2e63'
    STATUS_INFO = '#00d9ff'
    
    # Borders
    BORDER_LIGHT = '#2d3561'
    BORDER_GLOW = '#00d9ff'

# Configuration
SIM_FILE_PATH = get_resource_path("data/Hybrid_malware.csv") # Your simulated CSV file path

class MalwareDetectorUI:
    """Cybersecurity Professional GUI"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("STRIKE | Stealth Threat Recognition, Isolation, & Killing Engine")
        self.root.geometry("1400x900")
        self.root.configure(bg=CyberTheme.BG_DARK)
        
        # Apply custom style
        self.setup_custom_styles()
        
        # Initialize backend
        self.backend = BackendManager()
        try:
            self.backend.initialize_layers()
        except Exception as e:
            self.show_error_dialog("Initialization Error", f"Failed to initialize backend: {e}")
            return
        
        # Monitoring state
        self.monitoring_active = False
        self.sim_active = False
        self.sim_thread_id = 0
        self.auto_check_job = None      # Tracks the 10-second loop
        self.current_auto_mode = None
        self.update_job = None
        self.status_blink = False
        
        # Detection mode
        self.detection_mode = StringVar(value="hybrid") # Default to Hybrid mode
        
        # Create main layout
        self.create_navigation()
        self.create_pages()
        
        # Show dashboard by default
        self.show_page("dashboard")
        
        # Start status blink animation
        self.animate_status_indicator()
    
    def setup_custom_styles(self):
        """Configure custom ttk styles for cyber theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Treeview Main Body
        style.configure("Cyber.Treeview",
                       background=CyberTheme.BG_CARD,
                       foreground=CyberTheme.TEXT_PRIMARY, # This makes text LIGHT
                       fieldbackground=CyberTheme.BG_CARD,
                       borderwidth=0,
                       font=('Consolas', 9))
        
        # Treeview Headings
        style.configure("Cyber.Treeview.Heading",
                       background=CyberTheme.BG_PANEL,
                       foreground=CyberTheme.ACCENT_CYAN,
                       borderwidth=1,
                       relief='flat',
                       font=('Segoe UI', 9, 'bold'))
        
        # Treeview Selection Colors
        style.map('Cyber.Treeview',
                 background=[('selected', CyberTheme.BG_HOVER)],
                 foreground=[('selected', CyberTheme.ACCENT_CYAN)]) # Light Cyan text when selected
        
        # Notebook Style
        style.configure("Cyber.TNotebook",
                       background=CyberTheme.BG_PANEL,
                       borderwidth=0)
        style.configure("Cyber.TNotebook.Tab",
                       background=CyberTheme.BG_CARD,
                       foreground=CyberTheme.TEXT_SECONDARY,
                       padding=[20, 10],
                       borderwidth=0,
                       font=('Segoe UI', 10))
        style.map("Cyber.TNotebook.Tab",
                 background=[('selected', CyberTheme.BG_PANEL)],
                 foreground=[('selected', CyberTheme.ACCENT_CYAN)])
        
        # Scrollbar Style
        style.configure("Cyber.Vertical.TScrollbar",
                       background=CyberTheme.BG_CARD,
                       troughcolor=CyberTheme.BG_PANEL,
                       borderwidth=0,
                       arrowcolor=CyberTheme.ACCENT_CYAN)
        style.configure("Cyber.Horizontal.TScrollbar",
                       background=CyberTheme.BG_CARD,
                       troughcolor=CyberTheme.BG_PANEL,
                       borderwidth=0,
                       arrowcolor=CyberTheme.ACCENT_CYAN)

    
    def create_navigation(self):
        """Create cyberpunk-style navigation bar"""
        nav_frame = Frame(self.root, bg=CyberTheme.BG_PANEL, height=70)
        nav_frame.pack(side=TOP, fill=X)
        nav_frame.pack_propagate(False)
        
        # Add subtle top border glow
        top_glow = Frame(nav_frame, bg=CyberTheme.ACCENT_CYAN, height=2)
        top_glow.pack(side=TOP, fill=X)
        
        # Content container
        nav_content = Frame(nav_frame, bg=CyberTheme.BG_PANEL)
        nav_content.pack(fill=BOTH, expand=True)
        
        # Logo/Title Section
        logo_frame = Frame(nav_content, bg=CyberTheme.BG_PANEL)
        logo_frame.pack(side=LEFT, padx=20)
        
        title_label = Label(logo_frame, text="⬢ STRIKE", 
                           bg=CyberTheme.BG_PANEL, 
                           fg=CyberTheme.ACCENT_CYAN, 
                           font=("Segoe UI", 20, "bold"))
        title_label.pack(side=LEFT, pady=15)
        
        subtitle = Label(logo_frame, text="STEALTH RECOGNITION & ELIMINATION", 
                        bg=CyberTheme.BG_PANEL, 
                        fg=CyberTheme.TEXT_DIM, 
                        font=("Consolas", 8))
        subtitle.pack(side=LEFT, padx=10, pady=15)
        
        # Navigation Buttons
        nav_buttons = Frame(nav_content, bg=CyberTheme.BG_PANEL)
        nav_buttons.pack(side=LEFT, padx=20)
        
        self.nav_btn_refs = {}
        pages = [
            ("DASHBOARD", "dashboard", "⬢"),
            ("STATIC", "static", "◈"),
            ("DYNAMIC", "dynamic", "◆"),
            ("NETWORK", "network", "◇"),
            ("ALERTS", "alerts", "⬡"),
            ("SETTINGS", "settings", "⚙")
        ]
        
        for text, page, icon in pages:
            btn = self.create_nav_button(nav_buttons, f"{icon} {text}", page)
            btn.pack(side=LEFT, padx=2)
            self.nav_btn_refs[page] = btn
        
        # Status Indicator (Right Side)
        status_frame = Frame(nav_content, bg=CyberTheme.BG_PANEL)
        status_frame.pack(side=RIGHT, padx=20)
        
        # Live status indicator
        self.status_indicator = Label(status_frame, text="●", 
                                      bg=CyberTheme.BG_PANEL, 
                                      fg=CyberTheme.TEXT_DIM, 
                                      font=("Arial", 20))
        self.status_indicator.pack(side=LEFT, padx=5)

        # Add this to status_frame in create_navigation
        self.scan_line = Label(status_frame, text="", 
                            bg=CyberTheme.BG_PANEL, 
                            fg=CyberTheme.ACCENT_CYAN, 
                            font=("Consolas", 8, "italic"))
        self.scan_line.pack(side=LEFT, padx=10)
        
        self.status_text = Label(status_frame, text="ENGINE OFFLINE", 
                                bg=CyberTheme.BG_PANEL, 
                                fg=CyberTheme.TEXT_DIM, 
                                font=("Consolas", 10, "bold"))
        self.status_text.pack(side=LEFT, padx=5)
        
        # Control Buttons
        controls = Frame(nav_content, bg=CyberTheme.BG_PANEL)
        controls.pack(side=RIGHT, padx=10)
        
        self.stop_btn = self.create_control_button(controls, "⏹ STOP", 
                                                   self.stop_monitoring, 
                                                   CyberTheme.ACCENT_RED,
                                                   state=DISABLED)
        self.stop_btn.pack(side=RIGHT, padx=3)
        
        self.start_btn = self.create_control_button(controls, "▶ ENGAGE SYSTEM", 
                                                    self.start_smart_monitoring,
                                                    CyberTheme.ACCENT_GREEN)
        self.start_btn.pack(side=RIGHT, padx=3)
    
    def create_nav_button(self, parent, text, page):
        """Create cyberpunk navigation button"""
        btn = Label(parent, text=text,
                   bg=CyberTheme.BG_CARD,
                   fg=CyberTheme.TEXT_SECONDARY,
                   font=("Segoe UI", 9, "bold"),
                   padx=15, pady=10,
                   cursor="hand2")
        
        def on_enter(e):
            if not hasattr(btn, 'active') or not btn.active:
                btn.config(bg=CyberTheme.BG_HOVER, fg=CyberTheme.TEXT_PRIMARY)
        
        def on_leave(e):
            if not hasattr(btn, 'active') or not btn.active:
                btn.config(bg=CyberTheme.BG_CARD, fg=CyberTheme.TEXT_SECONDARY)
        
        def on_click(e):
            self.show_page(page)
        
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        btn.bind("<Button-1>", on_click)
        btn.active = False
        
        return btn
    
    def create_control_button(self, parent, text, command, color, state=NORMAL):
        """Create glowing control button"""
        btn = Button(parent, text=text,
                    command=command,
                    bg=color,
                    fg=CyberTheme.BG_DARK,
                    activebackground=color,
                    activeforeground=CyberTheme.BG_DARK,
                    font=("Segoe UI", 9, "bold"),
                    bd=0,
                    padx=15, pady=8,
                    cursor="hand2",
                    state=state,
                    relief=FLAT)
        
        def on_enter(e):
            if btn['state'] != DISABLED:
                btn.config(bg=self.lighten_color(color))
        
        def on_leave(e):
            if btn['state'] != DISABLED:
                btn.config(bg=color)
        
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        
        return btn
    
    def lighten_color(self, hex_color):
        """Lighten a hex color by 20%"""
        hex_color = hex_color.lstrip('#')
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        r = min(255, int(r * 1.2))
        g = min(255, int(g * 1.2))
        b = min(255, int(b * 1.2))
        return f'#{r:02x}{g:02x}{b:02x}'
    
    def create_pages(self):
        """Create container for all pages"""
        self.pages_container = Frame(self.root, bg=CyberTheme.BG_DARK)
        self.pages_container.pack(fill=BOTH, expand=True)
        self.pages = {}
        
        self.pages['dashboard'] = self.create_dashboard_page()
        self.pages['static'] = self.create_static_page()
        self.pages['dynamic'] = self.create_dynamic_page()
        self.pages['network'] = self.create_network_page()
        self.pages['alerts'] = self.create_alerts_page()
        self.pages['settings'] = self.create_settings_page()
    
    def show_page(self, page_name):
        """Show selected page and update nav buttons"""
        for name, page in self.pages.items():
            if name == page_name:
                page.pack(fill=BOTH, expand=True)
            else:
                page.pack_forget()
        
        # Update navigation button states
        for name, btn in self.nav_btn_refs.items():
            if name == page_name:
                btn.config(bg=CyberTheme.BG_PANEL, 
                          fg=CyberTheme.ACCENT_CYAN,
                          relief=FLAT)
                btn.active = True
            else:
                btn.config(bg=CyberTheme.BG_CARD, 
                          fg=CyberTheme.TEXT_SECONDARY,
                          relief=FLAT)
                btn.active = False
    
    # ==================== DASHBOARD PAGE ====================
    def create_dashboard_page(self):
        """Create futuristic dashboard with metrics cards"""
        page = Frame(self.pages_container, bg=CyberTheme.BG_DARK)
        
        # Header
        header = self.create_page_header(page, "◈ SYSTEM DASHBOARD", 
                                         "Real-time threat monitoring and statistics")
        
        # Content
        content = Frame(page, bg=CyberTheme.BG_DARK)
        content.pack(fill=BOTH, expand=True, padx=20, pady=20)
        
        # Score Cards Row
        cards_frame = Frame(content, bg=CyberTheme.BG_DARK)
        cards_frame.pack(fill=X, pady=(0, 20))
        
        self.dash_static_score = self.create_cyber_card(
            cards_frame, "STATIC LAYER", "0.00", CyberTheme.ACCENT_CYAN, "◈"
        )
        self.dash_dynamic_score = self.create_cyber_card(
            cards_frame, "DYNAMIC LAYER", "0.00", CyberTheme.ACCENT_YELLOW, "◆"
        )
        self.dash_network_score = self.create_cyber_card(
            cards_frame, "NETWORK LAYER", "0.00", CyberTheme.ACCENT_PURPLE, "◇"
        )
        self.dash_ensemble_score = self.create_cyber_card(
            cards_frame, "ENSEMBLE SCORE", "0.00", CyberTheme.ACCENT_GREEN, "⬢"
        )
        
        # Two Column Layout
        columns = Frame(content, bg=CyberTheme.BG_DARK)
        columns.pack(fill=BOTH, expand=True)
        
        left_col = Frame(columns, bg=CyberTheme.BG_DARK)
        left_col.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 10))
        
        right_col = Frame(columns, bg=CyberTheme.BG_DARK)
        right_col.pack(side=RIGHT, fill=BOTH, expand=True)
        
        # System Status Panel
        status_panel = self.create_panel(left_col, "⬢ SYSTEM STATUS")
        
        self.status_label = Label(status_panel, text="Status: Idle", 
                                 font=("Consolas", 12, "bold"), 
                                 bg=CyberTheme.BG_CARD, 
                                 fg=CyberTheme.TEXT_PRIMARY,
                                 anchor=W)
        self.status_label.pack(fill=X, padx=15, pady=10)
        
        self.ensemble_label = Label(status_panel, text="Verdict: Unknown", 
                                   font=("Consolas", 11), 
                                   bg=CyberTheme.BG_CARD, 
                                   fg=CyberTheme.TEXT_SECONDARY,
                                   anchor=W)
        self.ensemble_label.pack(fill=X, padx=15, pady=(0, 10))
        
        # Statistics Panel
        stats_panel = self.create_panel(left_col, "◈ STATISTICS")
        
        self.stats_tree = ttk.Treeview(stats_panel, 
                                       columns=("value",), 
                                       height=10,
                                       style="Cyber.Treeview")
        self.stats_tree.heading("#0", text="METRIC")
        self.stats_tree.heading("value", text="VALUE")
        self.stats_tree.column("#0", width=300)
        self.stats_tree.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Recent Alerts Panel
        alerts_panel = self.create_panel(right_col, "⬡ RECENT ALERTS")
        
        self.dash_alerts_tree = ttk.Treeview(alerts_panel, 
                                             columns=("time", "label", "score"),
                                             height=18,
                                             style="Cyber.Treeview")
        self.dash_alerts_tree.heading("#0", text="")
        self.dash_alerts_tree.heading("time", text="TIME")
        self.dash_alerts_tree.heading("label", text="THREAT TYPE")
        self.dash_alerts_tree.heading("score", text="SCORE")
        self.dash_alerts_tree.column("#0", width=0, stretch=False)
        self.dash_alerts_tree.column("time", width=100)
        self.dash_alerts_tree.column("label", width=200)
        self.dash_alerts_tree.column("score", width=80)
        self.dash_alerts_tree.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        return page
    
    def create_cyber_card(self, parent, title, value, color, icon):
        """Create glowing metric card"""
        card = Frame(parent, bg=CyberTheme.BG_CARD, relief=FLAT, bd=0)
        card.pack(side=LEFT, fill=BOTH, expand=True, padx=8)
        
        # Colored top border
        border = Frame(card, bg=color, height=3)
        border.pack(fill=X)
        
        # Icon
        icon_label = Label(card, text=icon, 
                          bg=CyberTheme.BG_CARD, 
                          fg=color, 
                          font=("Arial", 24))
        icon_label.pack(pady=(15, 5))
        
        # Title
        title_label = Label(card, text=title, 
                           bg=CyberTheme.BG_CARD, 
                           fg=CyberTheme.TEXT_SECONDARY, 
                           font=("Segoe UI", 9))
        title_label.pack()
        
        # Value
        value_label = Label(card, text=value, 
                           bg=CyberTheme.BG_CARD, 
                           fg=color, 
                           font=("Consolas", 28, "bold"))
        value_label.pack(pady=(5, 20))
        
        return value_label
    
    def create_page_header(self, parent, title, subtitle=""):
        """Create consistent page header"""
        header = Frame(parent, bg=CyberTheme.BG_PANEL)
        header.pack(fill=X)
        
        # Top glow line
        Frame(header, bg=CyberTheme.ACCENT_CYAN, height=2).pack(fill=X)
        
        content = Frame(header, bg=CyberTheme.BG_PANEL)
        content.pack(fill=X, padx=30, pady=20)
        
        Label(content, text=title, 
              font=("Segoe UI", 22, "bold"), 
              bg=CyberTheme.BG_PANEL, 
              fg=CyberTheme.TEXT_PRIMARY).pack(anchor=W)
        
        if subtitle:
            Label(content, text=subtitle, 
                  font=("Consolas", 9), 
                  bg=CyberTheme.BG_PANEL, 
                  fg=CyberTheme.TEXT_DIM).pack(anchor=W, pady=(5, 0))
        
        return header
    
    def create_panel(self, parent, title):
        """Create bordered panel with title"""
        container = Frame(parent, bg=CyberTheme.BG_DARK)
        container.pack(fill=BOTH, expand=True, pady=(0, 15))
        
        # Title bar
        title_bar = Frame(container, bg=CyberTheme.BG_PANEL, height=40)
        title_bar.pack(fill=X)
        title_bar.pack_propagate(False)
        
        Label(title_bar, text=title, 
              font=("Consolas", 10, "bold"), 
              bg=CyberTheme.BG_PANEL, 
              fg=CyberTheme.ACCENT_CYAN).pack(side=LEFT, padx=15, pady=10)
        
        # Content area
        panel = Frame(container, bg=CyberTheme.BG_CARD)
        panel.pack(fill=BOTH, expand=True)
        
        return panel
    
    # ==================== STATIC PAGE ====================
    def create_static_page(self):
        """File analysis page with cyber styling"""
        page = Frame(self.pages_container, bg=CyberTheme.BG_DARK)
        
        header = self.create_page_header(page, "◈ STATIC FILE ANALYSIS", 
                                         "Deep scan and forensic analysis of suspicious files")
        
        # Controls Panel
        controls_panel = self.create_panel(page, "⬢ FILE SCANNER")
        controls_panel.pack(fill=X, padx=20, pady=20)
        
        controls = Frame(controls_panel, bg=CyberTheme.BG_CARD)
        controls.pack(fill=X, padx=15, pady=15)
        
        Label(controls, text="TARGET FILE:", 
              bg=CyberTheme.BG_CARD, 
              fg=CyberTheme.TEXT_SECONDARY,
              font=("Consolas", 9)).pack(side=LEFT, padx=(0, 10))
        
        self.static_path_var = StringVar()
        path_entry = Entry(controls, 
                          textvariable=self.static_path_var, 
                          width=70,
                          bg=CyberTheme.BG_PANEL,
                          fg=CyberTheme.TEXT_PRIMARY,
                          insertbackground=CyberTheme.ACCENT_CYAN,
                          font=("Consolas", 10),
                          bd=0,
                          relief=FLAT)
        path_entry.pack(side=LEFT, padx=5, ipady=5)
        
        self.create_action_button(controls, "BROWSE", 
                                 self.browse_file, 
                                 CyberTheme.TEXT_SECONDARY).pack(side=LEFT, padx=5)
        
        self.create_action_button(controls, "◈ SCAN", 
                                 self.scan_static_file, 
                                 CyberTheme.ACCENT_CYAN).pack(side=LEFT, padx=5)
        
        self.create_action_button(controls, "⬢ QUARANTINE", 
                                 self.quarantine_file, 
                                 CyberTheme.ACCENT_RED).pack(side=LEFT, padx=5)
        
        # Results Area
        results = Frame(page, bg=CyberTheme.BG_DARK)
        results.pack(fill=BOTH, expand=True, padx=20, pady=(0, 20))
        
        # File Details Panel
        details_panel = self.create_panel(results, "◆ FILE DETAILS")
        details_panel.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 10))
        
        self.static_details_tree = ttk.Treeview(details_panel, 
                                                columns=("value",), 
                                                height=15,
                                                style="Cyber.Treeview")
        self.static_details_tree.heading("#0", text="PROPERTY")
        self.static_details_tree.heading("value", text="VALUE")
        self.static_details_tree.column("#0", width=200)
        self.static_details_tree.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Scan History Panel
        history_panel = self.create_panel(results, "◇ SCAN HISTORY")
        history_panel.pack(side=RIGHT, fill=BOTH, expand=True)
        
        self.static_history_tree = ttk.Treeview(history_panel, 
                                                columns=("file", "score", "label"), 
                                                height=15,
                                                style="Cyber.Treeview")
        self.static_history_tree.heading("#0", text="")
        self.static_history_tree.heading("file", text="FILE")
        self.static_history_tree.heading("score", text="SCORE")
        self.static_history_tree.heading("label", text="VERDICT")
        self.static_history_tree.column("#0", width=0)
        self.static_history_tree.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        return page
    
    def create_action_button(self, parent, text, command, color):
        """Create styled action button"""
        btn = Button(parent, text=text,
                    command=command,
                    bg=CyberTheme.BG_PANEL,
                    fg=color,
                    activebackground=CyberTheme.BG_HOVER,
                    activeforeground=color,
                    font=("Consolas", 9, "bold"),
                    bd=1,
                    relief=SOLID,
                    borderwidth=1,
                    padx=12, pady=6,
                    cursor="hand2")
        btn.config(highlightbackground=color, highlightcolor=color)
        return btn
    
    # ==================== DYNAMIC PAGE ====================
    def create_dynamic_page(self):
        """Process monitoring with live data feeds (Updated for Real-Time Stats)"""
        page = Frame(self.pages_container, bg=CyberTheme.BG_DARK)
        
        header = self.create_page_header(page, "◆ DYNAMIC ANALYSIS", 
                                         "Real-time behavioral monitoring and threat detection")
        
        # Tabs
        self.dyn_tabs = ttk.Notebook(page, style="Cyber.TNotebook")
        self.dyn_tabs.pack(fill=BOTH, expand=True, padx=20, pady=20)
        
        self.tab_live = Frame(self.dyn_tabs, bg=CyberTheme.BG_CARD)
        self.tab_csv = Frame(self.dyn_tabs, bg=CyberTheme.BG_CARD)
        
        self.dyn_tabs.add(self.tab_live, text="  ⬢ LIVE MONITOR  ")
        self.dyn_tabs.add(self.tab_csv, text="  ◈ THREAT ANALYSIS  ")
        
        # --- TAB 1: LIVE MONITOR (REAL SYSTEM STATS) ---
        live_frame = Frame(self.tab_live, bg=CyberTheme.BG_CARD)
        live_frame.pack(fill=BOTH, expand=True, padx=15, pady=15)
        
        self.lbl_dyn_status = Label(live_frame, 
                                    text="● STANDBY", 
                                    font=("Consolas", 10, "bold"), 
                                    bg=CyberTheme.BG_CARD, 
                                    fg=CyberTheme.TEXT_DIM)
        self.lbl_dyn_status.pack(anchor=W, pady=(0, 10))
        
        # NEW COLUMNS: Showing real psutil data instead of empty features
        columns_live = ["time", "pid", "name", "status", "cpu", "mem"]
        
        tree_frame = Frame(live_frame, bg=CyberTheme.BG_CARD)
        tree_frame.pack(fill=BOTH, expand=True)
        
        self.tree_live = ttk.Treeview(tree_frame, 
                                      columns=columns_live, 
                                      show="headings", 
                                      height=15, 
                                      style="Cyber.Treeview")
        
        self.tree_live.heading("time", text="TIME")
        self.tree_live.column("time", width=100, anchor=CENTER)
        
        self.tree_live.heading("pid", text="PID")
        self.tree_live.column("pid", width=80, anchor=CENTER)
        
        self.tree_live.heading("name", text="PROCESS NAME")
        self.tree_live.column("name", width=250, anchor=W)
        
        self.tree_live.heading("status", text="STATUS")
        self.tree_live.column("status", width=120, anchor=CENTER)
        
        self.tree_live.heading("cpu", text="CPU %")
        self.tree_live.column("cpu", width=100, anchor=CENTER)
        
        self.tree_live.heading("mem", text="MEM %")
        self.tree_live.column("mem", width=100, anchor=CENTER)
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient=VERTICAL, 
                           command=self.tree_live.yview,
                           style="Cyber.Vertical.TScrollbar")
        hsb = ttk.Scrollbar(tree_frame, orient=HORIZONTAL, 
                           command=self.tree_live.xview,
                           style="Cyber.Horizontal.TScrollbar")
        self.tree_live.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree_live.pack(side=LEFT, fill=BOTH, expand=True)
        vsb.pack(side=RIGHT, fill=Y)
        hsb.pack(side=BOTTOM, fill=X)
        
        # --- TAB 2: THREAT ANALYSIS (CSV) ---
        csv_frame = Frame(self.tab_csv, bg=CyberTheme.BG_CARD)
        csv_frame.pack(fill=BOTH, expand=True, padx=15, pady=15)
        
        self.lbl_csv_info = Label(csv_frame, 
                                  text="Awaiting system activation...", 
                                  font=("Consolas", 10), 
                                  bg=CyberTheme.BG_CARD, 
                                  fg=CyberTheme.TEXT_DIM)
        self.lbl_csv_info.pack(pady=(0, 10))
        
        columns_csv = ("pid", "name", "risk", "status")
        self.tree_csv = ttk.Treeview(csv_frame, 
                                     columns=columns_csv, 
                                     show="headings", 
                                     height=15,
                                     style="Cyber.Treeview")
        
        self.tree_csv.heading("pid", text="PID")
        self.tree_csv.heading("name", text="TARGET RESOURCE")
        self.tree_csv.heading("risk", text="RISK SCORE")
        self.tree_csv.heading("status", text="STATUS")
        
        self.tree_csv.column("pid", width=80, anchor=CENTER)
        self.tree_csv.column("name", width=300)
        self.tree_csv.column("risk", width=120, anchor=CENTER)
        self.tree_csv.column("status", width=120, anchor=CENTER)
        
        scroll_csv = ttk.Scrollbar(csv_frame, orient=VERTICAL, 
                                   command=self.tree_csv.yview,
                                   style="Cyber.Vertical.TScrollbar")
        self.tree_csv.configure(yscroll=scroll_csv.set)
        
        self.tree_csv.pack(side=LEFT, fill=BOTH, expand=True)
        scroll_csv.pack(side=RIGHT, fill=Y)
        
        self.tree_csv.tag_configure("malicious", 
                                    background=CyberTheme.ACCENT_RED,
                                    foreground=CyberTheme.BG_DARK)
        self.tree_csv.tag_configure("safe", 
                                    background=CyberTheme.BG_CARD)
        
        return page 
    
    
    # ==================== NETWORK PAGE ====================
    def create_network_page(self):
        """Network traffic analysis with threat detection"""
        page = Frame(self.pages_container, bg=CyberTheme.BG_DARK)
        
        header = self.create_page_header(page, "◇ NETWORK ANALYSIS", 
                                         "Monitor traffic patterns and detect C2 communications")
        
        # Stats Bar
        stats_bar = Frame(page, bg=CyberTheme.BG_PANEL)
        stats_bar.pack(fill=X, padx=20, pady=(20, 0))
        
        Frame(stats_bar, bg=CyberTheme.ACCENT_PURPLE, height=2).pack(fill=X)
        
        stats_content = Frame(stats_bar, bg=CyberTheme.BG_PANEL)
        stats_content.pack(fill=X, padx=20, pady=15)
        
        self.net_bps_label = Label(stats_content, 
                                   text="⬢ BANDWIDTH: 0 KB/s", 
                                   font=("Consolas", 11, "bold"), 
                                   bg=CyberTheme.BG_PANEL, 
                                   fg=CyberTheme.ACCENT_CYAN)
        self.net_bps_label.pack(side=LEFT, padx=20)
        
        self.net_conns_label = Label(stats_content, 
                                     text="◆ CONNECTIONS: 0", 
                                     font=("Consolas", 11, "bold"), 
                                     bg=CyberTheme.BG_PANEL, 
                                     fg=CyberTheme.ACCENT_YELLOW)
        self.net_conns_label.pack(side=LEFT, padx=20)
        
        self.net_ips_label = Label(stats_content, 
                                   text="◇ UNIQUE IPs: 0", 
                                   font=("Consolas", 11, "bold"), 
                                   bg=CyberTheme.BG_PANEL, 
                                   fg=CyberTheme.ACCENT_PURPLE)
        self.net_ips_label.pack(side=LEFT, padx=20)
        
        # Tabs
        self.net_tabs = ttk.Notebook(page, style="Cyber.TNotebook")
        self.net_tabs.pack(fill=BOTH, expand=True, padx=20, pady=20)
        
        self.tab_net_live = Frame(self.net_tabs, bg=CyberTheme.BG_CARD)
        self.tab_net_sim = Frame(self.net_tabs, bg=CyberTheme.BG_CARD)
        
        self.net_tabs.add(self.tab_net_live, text="  ⬢ LIVE TRAFFIC  ")
        self.net_tabs.add(self.tab_net_sim, text="  ⬡ THREAT DETECTION  ")
        
        # Tab 1: Live Traffic
        live_frame = Frame(self.tab_net_live, bg=CyberTheme.BG_CARD)
        live_frame.pack(fill=BOTH, expand=True, padx=15, pady=15)
        
        cols_live = ("time", "local", "remote", "status", "pid")
        self.tree_net_live = ttk.Treeview(live_frame, 
                                          columns=cols_live, 
                                          show="headings", 
                                          height=15,
                                          style="Cyber.Treeview")
        
        self.tree_net_live.heading("time", text="TIME")
        self.tree_net_live.heading("local", text="LOCAL ADDRESS")
        self.tree_net_live.heading("remote", text="REMOTE ADDRESS")
        self.tree_net_live.heading("status", text="STATUS")
        self.tree_net_live.heading("pid", text="PID")
        
        self.tree_net_live.column("time", width=100)
        self.tree_net_live.column("local", width=180)
        self.tree_net_live.column("remote", width=180)
        self.tree_net_live.column("status", width=120)
        self.tree_net_live.column("pid", width=80)
        
        scroll_live = ttk.Scrollbar(live_frame, orient=VERTICAL, 
                                    command=self.tree_net_live.yview,
                                    style="Cyber.Vertical.TScrollbar")
        self.tree_net_live.configure(yscroll=scroll_live.set)
        self.tree_net_live.pack(side=LEFT, fill=BOTH, expand=True)
        scroll_live.pack(side=RIGHT, fill=Y)
        
        # Tab 2: Threat Detection
        sim_frame = Frame(self.tab_net_sim, bg=CyberTheme.BG_CARD)
        sim_frame.pack(fill=BOTH, expand=True, padx=15, pady=15)
        
        cols_sim = ("time", "process", "remote", "risk", "status")
        self.tree_net_sim = ttk.Treeview(sim_frame, 
                                         columns=cols_sim, 
                                         show="headings", 
                                         height=15,
                                         style="Cyber.Treeview")
        
        self.tree_net_sim.heading("time", text="TIME")
        self.tree_net_sim.heading("process", text="PROCESS PID")
        self.tree_net_sim.heading("remote", text="DESTINATION")
        self.tree_net_sim.heading("risk", text="RISK SCORE")
        self.tree_net_sim.heading("status", text="DETECTION")
        
        self.tree_net_sim.column("time", width=100)
        self.tree_net_sim.column("process", width=120)
        self.tree_net_sim.column("remote", width=220)
        self.tree_net_sim.column("risk", width=120)
        self.tree_net_sim.column("status", width=140)
        
        scroll_sim = ttk.Scrollbar(sim_frame, orient=VERTICAL, 
                                   command=self.tree_net_sim.yview,
                                   style="Cyber.Vertical.TScrollbar")
        self.tree_net_sim.configure(yscroll=scroll_sim.set)
        self.tree_net_sim.pack(side=LEFT, fill=BOTH, expand=True)
        scroll_sim.pack(side=RIGHT, fill=Y)
        
        self.tree_net_sim.tag_configure("malicious", 
                                        background=CyberTheme.ACCENT_RED,
                                        foreground=CyberTheme.BG_DARK)
        self.tree_net_sim.tag_configure("safe", 
                                        background=CyberTheme.BG_CARD)
        
        return page
    
    # ==================== ALERTS PAGE ====================
    def create_alerts_page(self):
        """Threat intelligence and forensics"""
        page = Frame(self.pages_container, bg=CyberTheme.BG_DARK)
        
        header = self.create_page_header(page, "⬡ THREAT INTELLIGENCE", 
                                         "Advanced threat correlation and attack visualization")
        
        # Control Bar
        controls_bar = Frame(page, bg=CyberTheme.BG_PANEL)
        controls_bar.pack(fill=X, padx=20, pady=(20, 0))
        
        Frame(controls_bar, bg=CyberTheme.ACCENT_RED, height=2).pack(fill=X)
        
        controls = Frame(controls_bar, bg=CyberTheme.BG_PANEL)
        controls.pack(fill=X, padx=15, pady=12)
        
        self.create_action_button(controls, "🗑 CLEAR ALERTS", 
                                 self.clear_alerts, 
                                 CyberTheme.TEXT_SECONDARY).pack(side=LEFT, padx=5)
        
        self.create_action_button(controls, "💾 EXPORT LOGS", 
                                 self.export_logs, 
                                 CyberTheme.ACCENT_CYAN).pack(side=LEFT, padx=5)
        
        self.create_action_button(controls, "🔄 REFRESH", 
                                 self.update_alert_visualization, 
                                 CyberTheme.ACCENT_GREEN).pack(side=LEFT, padx=5)
        
        self.create_action_button(controls, "DISINFECT", 
                                 self.disinfect_system, 
                                 CyberTheme.ACCENT_RED).pack(side=LEFT, padx=5)
        
        # Tabs
        self.alert_tabs = ttk.Notebook(page, style="Cyber.TNotebook")
        self.alert_tabs.pack(fill=BOTH, expand=True, padx=20, pady=20)
        
        self.tab_alert_vis = Frame(self.alert_tabs, bg=CyberTheme.BG_CARD)
        self.tab_alert_list = Frame(self.alert_tabs, bg=CyberTheme.BG_CARD)
        
        self.alert_tabs.add(self.tab_alert_vis, text="  ⬢ ATTACK GRAPH  ")
        self.alert_tabs.add(self.tab_alert_list, text="  ◈ ALERT LOGS  ")
        
        # Tab 1: Visualization
        vis_frame = Frame(self.tab_alert_vis, bg=CyberTheme.BG_CARD)
        vis_frame.pack(fill=BOTH, expand=True, padx=15, pady=15)
        
        vis_title = Label(vis_frame, 
                         text="◆ PROCESS-TO-NETWORK CORRELATION MAP", 
                         bg=CyberTheme.BG_CARD, 
                         fg=CyberTheme.ACCENT_CYAN,
                         font=("Consolas", 11, "bold"))
        vis_title.pack(pady=(0, 10))
        
        # Matplotlib canvas with dark theme
        self.alert_fig, self.alert_ax = plt.subplots(figsize=(12, 7), dpi=100)
        self.alert_fig.patch.set_facecolor(CyberTheme.BG_CARD)
        self.alert_ax.set_facecolor(CyberTheme.BG_CARD)
        self.alert_ax.axis('off')
        
        self.alert_canvas = FigureCanvasTkAgg(self.alert_fig, master=vis_frame)
        self.alert_canvas.get_tk_widget().pack(fill=BOTH, expand=True)
        
        # Tab 2: Alert Logs
        log_frame = Frame(self.tab_alert_list, bg=CyberTheme.BG_CARD)
        log_frame.pack(fill=BOTH, expand=True, padx=15, pady=15)
        
        cols = ("time", "label", "confidence", "reason")
        self.alerts_tree = ttk.Treeview(log_frame, 
                                        columns=cols, 
                                        show="headings", 
                                        height=15,
                                        style="Cyber.Treeview")
        
        self.alerts_tree.heading("time", text="TIMESTAMP")
        self.alerts_tree.heading("label", text="THREAT TYPE")
        self.alerts_tree.heading("confidence", text="RISK")
        self.alerts_tree.heading("reason", text="ANALYSIS")
        
        self.alerts_tree.column("time", width=120)
        self.alerts_tree.column("label", width=180)
        self.alerts_tree.column("confidence", width=100, anchor=CENTER)
        self.alerts_tree.column("reason", width=500)
        
        self.alerts_tree.pack(fill=BOTH, expand=True)
        
        return page
    

    # ====================Disinfect System====================
    def disinfect_system(self):
        """Kill the host_agent.py process, stop the CSV simulation stream, and delete the file"""
        import psutil
        import os 
        
        # 1. Halt the CSV stream, BUT LEAVE THE ENGINE ONLINE
        if self.sim_active:
            self.sim_active = False
            self.log_message("[DISINFECT] data stream halted.")
        
        # 2. Hunt down and terminate host_agent.py
        agent_killed = False
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info['cmdline']
                # Check if it's a python process and running host_agent.py
                if cmdline and any('host_agent.py' in cmd for cmd in cmdline):
                    proc.kill() # Force kill the malware agent
                    agent_killed = True
                    self.log_message(f"[DISINFECT] Neutralized host_agent.py (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # 3. Delete the malicious data stream file (CSV)
        file_deleted = False
        try:
            if os.path.exists(SIM_FILE_PATH):
                os.remove(SIM_FILE_PATH)
                self.log_message("[DISINFECT] Threat payload successfully deleted from disk.")
                file_deleted = True
        except Exception as e:
            self.log_message(f"[DISINFECT ERROR] Could not delete data file: {e}")
            
        # 4. Force an immediate auto-check so the UI instantly snaps back to SAFE Real-Time
        if self.monitoring_active:
            self.current_auto_mode = None  # Reset tracker to force a UI refresh
            self.auto_mode_check()         # Trigger the jump
        
        # 5. Provide Dynamic UI Feedback
        feedback_msg = "Data Exfiltration stopped."
        if agent_killed:
            feedback_msg += "\n✓ SCAN COMPLETED."
        if file_deleted:
            feedback_msg += "\n✓ Malicious payload file permanently deleted."
            
        if agent_killed or file_deleted:
            self.show_info_dialog("System Disinfected", f"Threat neutralized.\n\n{feedback_msg}")
            self.clear_alerts() # Clear the alerts board after disinfecting
        else:
            self.show_info_dialog("Disinfect Status", "Data stream stopped.\n\nNo active threats or payload files were found on the system.")

    # ==================== SETTINGS PAGE ====================
    def create_settings_page(self):
        """System configuration and ML training"""
        page = Frame(self.pages_container, bg=CyberTheme.BG_DARK)
        
        header = self.create_page_header(page, "⚙ SYSTEM CONFIGURATION", 
                                         "Model training and system diagnostics")
        
        content = Frame(page, bg=CyberTheme.BG_DARK)
        content.pack(fill=BOTH, expand=True, padx=20, pady=20)
        
        # ML Status Panel
        ml_panel = self.create_panel(content, "◈ MACHINE LEARNING STATUS")
        ml_panel.pack(fill=X, pady=(0, 15))
        
        status_frame = Frame(ml_panel, bg=CyberTheme.BG_CARD)
        status_frame.pack(fill=X, padx=15, pady=15)
        
        status_text = Text(status_frame, 
                          height=6, 
                          bg=CyberTheme.BG_PANEL,
                          fg=CyberTheme.TEXT_PRIMARY,
                          font=("Consolas", 10),
                          wrap=WORD,
                          bd=0,
                          relief=FLAT)
        status_text.pack(fill=X)
        
        ml_status = self.backend.get_ml_status()
        status_lines = [
            "ML MODEL STATUS:",
            f"  ◈ Static Layer:  {'✓ ENABLED' if ml_status['static'] else '✗ DISABLED'}",
            f"  ◆ Dynamic Layer: {'✓ ENABLED' if ml_status['dynamic'] else '✗ DISABLED'}",
            f"  ◇ Network Layer: {'✓ ENABLED' if ml_status['network'] else '✗ DISABLED'}",
        ]
        status_text.insert("1.0", "\n".join(status_lines))
        status_text.config(state=DISABLED)
        

        # Detection Mode Panel
        mode_panel = self.create_panel(content, "◇ DETECTION MODE")
        mode_panel.pack(fill=X, pady=(0, 15))
        
        mode_frame = Frame(mode_panel, bg=CyberTheme.BG_CARD)
        mode_frame.pack(fill=X, padx=15, pady=15)
        
        # Auto Mode description
        mode_desc = Label(mode_frame, 
                         text="System is running in AUTONOMOUS MODE.\nPayload presence is scanned every 10 seconds.",
                         bg=CyberTheme.BG_CARD,
                         fg=CyberTheme.TEXT_SECONDARY,
                         font=("Consolas", 10),
                         justify=LEFT)
        mode_desc.pack(anchor=W, pady=(0, 10))
        
        # Auto Mode status indicator
        self.mode_status_label = Label(mode_frame,
                                      text="AUTO-POLLING: ACTIVE",
                                      bg=CyberTheme.BG_CARD,
                                      fg=CyberTheme.ACCENT_CYAN,
                                      font=("Consolas", 10, "bold"))
        self.mode_status_label.pack(anchor=W)
        # -------------------------------------
        
        # Mode description
        mode_desc = Label(mode_frame, 
                         text="Choose detection mode:",
                         bg=CyberTheme.BG_CARD,
                         fg=CyberTheme.TEXT_SECONDARY,
                         font=("Consolas", 10))
        mode_desc.pack(anchor=W, pady=(0, 10))
        
        # Mode toggle frame
        toggle_frame = Frame(mode_frame, bg=CyberTheme.BG_CARD)
        toggle_frame.pack(fill=X, pady=(0, 10))
        
        # Hybrid mode option
        self.hybrid_radio = Radiobutton(toggle_frame,
                                       text="Refresh Datapipeline",
                                       variable=self.detection_mode,
                                       value="hybrid",
                                       bg=CyberTheme.BG_CARD,
                                       fg=CyberTheme.TEXT_PRIMARY,
                                       selectcolor=CyberTheme.BG_PANEL,
                                       activebackground=CyberTheme.BG_CARD,
                                       activeforeground=CyberTheme.ACCENT_CYAN,
                                       font=("Consolas", 10),
                                       command=self.update_detection_mode)
        self.hybrid_radio.pack(anchor=W, pady=2)
        
        # Real-time mode option
        self.realtime_radio = Radiobutton(toggle_frame,
                                         text="Refresh Only (Real-Time System Stats)",
                                         variable=self.detection_mode,
                                         value="realtime",
                                         bg=CyberTheme.BG_CARD,
                                         fg=CyberTheme.TEXT_PRIMARY,
                                         selectcolor=CyberTheme.BG_PANEL,
                                         activebackground=CyberTheme.BG_CARD,
                                         activeforeground=CyberTheme.ACCENT_CYAN,
                                         font=("Consolas", 10),
                                         command=self.update_detection_mode)
        self.realtime_radio.pack(anchor=W, pady=2)
        
        # Mode status indicator
        self.mode_status_label = Label(mode_frame,
                                      text="Current Mode: Hybrid ",
                                      bg=CyberTheme.BG_CARD,
                                      fg=CyberTheme.ACCENT_PURPLE,
                                      font=("Consolas", 9, "bold"))
        self.mode_status_label.pack(anchor=W, pady=(10, 0))
        
        # Training Panel
        train_panel = self.create_panel(content, "⬢ MODEL TRAINING")
        train_panel.pack(fill=X, pady=(0, 15))
        
        train_frame = Frame(train_panel, bg=CyberTheme.BG_CARD)
        train_frame.pack(fill=X, padx=15, pady=15)
        
        self.create_action_button(train_frame, "◈ TRAIN ALL MODELS", 
                                 self.train_ml_models, 
                                 CyberTheme.ACCENT_CYAN).pack(anchor=W)
        
        self.train_status_label = Label(train_frame, 
                                        text="", 
                                        bg=CyberTheme.BG_CARD, 
                                        fg=CyberTheme.ACCENT_GREEN,
                                        font=("Consolas", 9))
        self.train_status_label.pack(anchor=W, pady=(10, 0))
        
        # System Log Panel
        log_panel = self.create_panel(content, "◇ SYSTEM LOGS")
        log_panel.pack(fill=BOTH, expand=True)
        
        self.log_text = Text(log_panel, 
                            height=12, 
                            bg=CyberTheme.BG_PANEL,
                            fg=CyberTheme.ACCENT_GREEN,
                            font=("Consolas", 9),
                            wrap=WORD,
                            bd=0,
                            relief=FLAT,
                            insertbackground=CyberTheme.ACCENT_CYAN)
        self.log_text.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        return page
    
    def update_detection_mode(self):
        """Update detection mode based on user selection"""
        mode = self.detection_mode.get()
        if mode == "hybrid":
            self.mode_status_label.config(text="Current Mode: Hybrid ", 
                                        fg=CyberTheme.ACCENT_PURPLE)
            self.log_message(f"[MODE] Switched to Hybrid Detection Mode")
        else:  # realtime
            self.mode_status_label.config(text="Current Mode:  SAFE Real-Time ", 
                                        fg=CyberTheme.ACCENT_GREEN)
            self.log_message(f"[MODE] Switched to Real-Time Detection Mode")
    
    # ==================== MONITORING CONTROL ====================
    def start_smart_monitoring(self):
        """Start monitoring and trigger the auto-polling system"""
        self.backend.start_monitoring()
        self.monitoring_active = True
        
        # Update UI
        self.start_btn.config(state=DISABLED, text="SYSTEM ACTIVE")
        self.stop_btn.config(state=NORMAL)
        self.status_indicator.config(fg=CyberTheme.ACCENT_GREEN)
        self.status_text.config(text="ONLINE", fg=CyberTheme.ACCENT_GREEN)
        
        # Reset the mode tracker and immediately run the first check
        self.current_auto_mode = None
        self.auto_mode_check()
        
        # Start UI updates
        if self.update_job is None:
            self.schedule_updates()
    
    def stop_monitoring(self):
        """Stop monitoring system and cancel background loops"""
        self.backend.stop_monitoring()
        self.monitoring_active = False
        self.sim_active = False  # Kill CSV thread
        self.current_auto_mode = None
        
        # Cancel the 10-second auto-check loop
        if self.auto_check_job is not None:
            self.root.after_cancel(self.auto_check_job)
            self.auto_check_job = None
        
        self.start_btn.config(state=NORMAL, text="▶ ENGAGE SYSTEM")
        self.stop_btn.config(state=DISABLED)
        self.status_indicator.config(fg=CyberTheme.TEXT_DIM)
        self.status_text.config(text="OFFLINE", fg=CyberTheme.TEXT_DIM)
        self.status_label.config(text="Status: System Stopped", fg=CyberTheme.ACCENT_RED)
        self.log_message("[SYSTEM] Monitoring stopped. Auto-polling suspended.")
    
    def animate_status_indicator(self):
        """Animate status indicator when active"""
        if self.monitoring_active:
            self.status_blink = not self.status_blink
            if self.status_blink:
                self.status_indicator.config(fg=CyberTheme.ACCENT_GREEN)
            else:
                self.status_indicator.config(fg=self.lighten_color(CyberTheme.ACCENT_GREEN))
        
        self.root.after(500, self.animate_status_indicator)


    # ==================== AUTO-MODE CHECK ====================
    def auto_mode_check(self):
        """Automatically check for the CSV payload every 10 seconds and switch modes"""
        if not self.monitoring_active:
            self.auto_check_job = None
            return

        file_exists = os.path.exists(SIM_FILE_PATH)

        if file_exists and self.current_auto_mode != "hybrid":
            # --- SWITCH TO HYBRID (File Found) ---
            self.current_auto_mode = "hybrid"
            self.log_message("[AUTO-SYS] Payload detected. Engaging Hybrid Data Stream...")
            
            # Update Status and Verdict
            self.status_label.config(text="Status: SCAN MODE", fg=CyberTheme.ACCENT_PURPLE)
            self.ensemble_label.config(text="Verdict: SUSPICIOUS", fg=CyberTheme.ACCENT_RED)
            
            # Visual jump to Threat Analysis
            self.show_page("dynamic")
            if hasattr(self, 'dyn_tabs'):
                self.dyn_tabs.select(1)
                
            self.run_simulation_thread(SIM_FILE_PATH)

        elif not file_exists and self.current_auto_mode != "realtime":
            # --- SWITCH TO REAL-TIME (File Missing/Deleted) ---
            self.current_auto_mode = "realtime"
            self.sim_active = False # Safely kills the CSV thread if it was running
            
            self.log_message("[AUTO-SYS] No payload found. Engaging SAFE Real-Time Mode.")
            
            # Update Status and Verdict
            self.status_label.config(text="Status: SCAN MODE", fg=CyberTheme.ACCENT_GREEN)
            self.ensemble_label.config(text="Verdict: SAFE", fg=CyberTheme.ACCENT_GREEN)
            
            # Visual jump to Live Monitor
            self.show_page("dynamic")
            if hasattr(self, 'dyn_tabs'):
                self.dyn_tabs.select(0)

        # Schedule the next check in 10 seconds
        self.auto_check_job = self.root.after(10000, self.auto_mode_check)
    
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
            print(f"[UPDATE ERROR] {e}")
        
        self.update_job = self.root.after(1000, self.schedule_updates)
    
    def update_dashboard(self):
        """Update dashboard metrics and scores"""
        try:
            # 1. Fetch Scores (Ensure backend returns these correctly)
            _, dyn_score = self.backend.get_dynamic_snapshot()
            _, net_score = self.backend.get_network_snapshot()
            
            # Calculate simple ensemble
            ensemble_score = (dyn_score + net_score) / 2.0
            
            # Update Score Cards
            if hasattr(self, 'dash_dynamic_score'):
                self.dash_dynamic_score.config(text=f"{dyn_score:.2f}")
            if hasattr(self, 'dash_network_score'):
                self.dash_network_score.config(text=f"{net_score:.2f}")
            if hasattr(self, 'dash_ensemble_score'):
                self.dash_ensemble_score.config(text=f"{ensemble_score:.2f}")

            # 2. Update Statistics Tree
            stats = self.backend.get_statistics()
            if hasattr(self, 'stats_tree'):
                for item in self.stats_tree.get_children():
                    self.stats_tree.delete(item)
                
                self.stats_tree.insert("", END, text="Total Detections", 
                                       values=(stats.get('total_detections', 0),))
                self.stats_tree.insert("", END, text="Total Alerts", 
                                       values=(stats.get('total_alerts', 0),))
                self.stats_tree.insert("", END, text="Monitoring Active", 
                                       values=("YES" if stats.get('monitoring_active') else "NO",))
            
            # 3. Update Recent Alerts Preview
            if hasattr(self, 'dash_alerts_tree'):
                for item in self.dash_alerts_tree.get_children():
                    self.dash_alerts_tree.delete(item)
                
                for alert in self.backend.alerts[-5:]:
                    self.dash_alerts_tree.insert("", END, values=(
                        alert.get('timestamp', ''), 
                        alert.get('label', ''), 
                        f"{alert.get('confidence', 0):.2f}"
                    ))
        except Exception as e:
            print(f"[DASH UPDATE ERROR] {e}")
    
    def update_dynamic_view(self):
        """Update dynamic layer tables with Real-Time Stats"""
        try:
            status = self.backend.dynamic_layer.get_status()
            
            # 1. Update Live Table (Tab 1)
            if hasattr(self, 'tree_live'):
                for item in self.tree_live.get_children():
                    self.tree_live.delete(item)
                
                # Show last 50 records (Reversed for newest first)
                for row in reversed(status['realtime_data'][-50:]):
                    self.tree_live.insert("", "end", values=(
                        row.get('timestamp', ''),
                        row.get('pid', ''),
                        row.get('name', ''),
                        row.get('status', 'N/A'),
                        row.get('cpu', '0%'),
                        row.get('memory', '0%')
                    ))
            
            # 2. Update CSV Analysis Table (Tab 2)
            if hasattr(self, 'tree_csv'):
                for item in self.tree_csv.get_children():
                    self.tree_csv.delete(item)
                
                for row in status['csv_data'][-50:]:
                    tag = "malicious" if row['status'] == "MALICIOUS" else "safe"
                    self.tree_csv.insert("", "end", values=(
                        row.get('pid', ''), 
                        row.get('name', ''), 
                        f"{row.get('risk_score', 0):.4f}", 
                        row.get('status', '')
                    ), tags=(tag,))
        except Exception as e:
            print(f"[DYN UPDATE ERROR] {e}")
    
    def update_network_view(self):
        """Update network traffic tables"""
        if not self.backend:
            return
        
        try:
            status_data = self.backend.network_layer.get_status()
            stats = self.backend.network_layer.get_network_stats()
            
            # Update stats labels
            bps = stats.get('bytes_per_sec', 0)
            live_count = len(status_data['live_data'])
            
            if hasattr(self, 'net_bps_label'):
                self.net_bps_label.config(text=f"⬢ BANDWIDTH: {bps/1024:.1f} KB/s")
            
            if hasattr(self, 'net_conns_label'):
                self.net_conns_label.config(text=f"◆ CONNECTIONS: {live_count}")
            
            # Update live traffic table
            if hasattr(self, 'tree_net_live'):
                for item in self.tree_net_live.get_children():
                    self.tree_net_live.delete(item)
                
                for row in list(status_data['live_data'])[-50:][::-1]:
                    self.tree_net_live.insert("", "end", values=(
                        row.get('time', ''), 
                        row.get('local', ''), 
                        row.get('remote', ''), 
                        row.get('status', ''), 
                        row.get('pid', '')
                    ))
            
            # Update threat detection table
            if hasattr(self, 'tree_net_sim'):
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
            print(f"[NET UPDATE] {e}")
    
    def update_alerts_view(self):
        """Update alerts table and visualization"""
        # Update table
        if hasattr(self, 'alerts_tree'):
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
            
            for alert in self.backend.alerts:
                self.alerts_tree.insert("", 0, values=(
                    alert['timestamp'], 
                    alert['label'], 
                    f"{alert['confidence']:.2f}", 
                    alert['reason']
                ))
        
        # Update visualization
        self.update_alert_visualization()
    
    def update_alert_visualization(self):
        """Update attack correlation graph"""
        if not hasattr(self, 'alert_ax') or not hasattr(self, 'alert_canvas'):
            return
        
        try:
            self.alert_ax.clear()
            self.alert_ax.set_facecolor(CyberTheme.BG_CARD)
            self.alert_ax.axis('off')
            
            alerts = self.backend.get_alerts()[:6]
            
            if not alerts:
                self.alert_ax.text(0.5, 0.5, "⬢ SYSTEM SECURE\nNo Active Threats", 
                                  ha='center', va='center', 
                                  fontsize=18, 
                                  color=CyberTheme.ACCENT_GREEN,
                                  family='Consolas',
                                  weight='bold')
                self.alert_canvas.draw()
                return
            
            # Layout
            left_x = 0.15
            right_x = 0.85
            start_y = 0.9
            gap_y = 0.15
            
            # Column headers
            self.alert_ax.text(left_x, 1.0, "⬢ INFECTED PROCESSES", 
                              ha='center', fontsize=11, 
                              fontweight='bold', 
                              color=CyberTheme.ACCENT_RED,
                              family='Consolas')
            
            self.alert_ax.text(right_x, 1.0, "◇ C2 SERVERS", 
                              ha='center', fontsize=11, 
                              fontweight='bold', 
                              color=CyberTheme.ACCENT_YELLOW,
                              family='Consolas')
            
            # Draw connections
            for i, alert in enumerate(alerts):
                y = start_y - (i * gap_y)
                
                pid = alert.get('pid', '???')
                proc = alert.get('process', 'Unknown')
                ip = alert.get('ip', 'Unknown IP')
                risk = alert.get('confidence', 0.0)
                
                # Process node (left)
                self.alert_ax.plot(left_x, y, marker='o', markersize=18, 
                                  color=CyberTheme.ACCENT_RED, 
                                  markeredgecolor=CyberTheme.TEXT_PRIMARY, 
                                  markeredgewidth=2)
                
                self.alert_ax.text(left_x, y + 0.04, f"{proc}\n[PID: {pid}]", 
                                  ha='center', fontsize=9, 
                                  color=CyberTheme.TEXT_PRIMARY,
                                  family='Consolas',
                                  weight='bold')
                
                # IP node (right)
                self.alert_ax.plot(right_x, y, marker='s', markersize=18, 
                                  color=CyberTheme.ACCENT_YELLOW,
                                  markeredgecolor=CyberTheme.TEXT_PRIMARY,
                                  markeredgewidth=2)
                
                self.alert_ax.text(right_x, y + 0.04, f"C2 Server\n{ip}", 
                                  ha='center', fontsize=9, 
                                  color=CyberTheme.TEXT_PRIMARY,
                                  family='Consolas',
                                  weight='bold')
                
                # Connection line
                line_alpha = min(0.3 + (risk * 0.7), 1.0)
                self.alert_ax.plot([left_x+0.05, right_x-0.05], [y, y], 
                                  color=CyberTheme.ACCENT_RED, 
                                  linewidth=3, 
                                  linestyle='-',
                                  alpha=line_alpha)
                
                # Risk annotation
                self.alert_ax.text(0.5, y + 0.01, 
                                  f"◆ EXFILTRATION | RISK: {risk:.2f}", 
                                  ha='center', fontsize=8, 
                                  color=CyberTheme.ACCENT_CYAN,
                                  family='Consolas',
                                  weight='bold',
                                  bbox=dict(boxstyle='round,pad=0.3', 
                                          facecolor=CyberTheme.BG_PANEL, 
                                          edgecolor=CyberTheme.ACCENT_CYAN,
                                          linewidth=1))
            
            self.alert_canvas.draw()
        
        except Exception as e:
            print(f"[ALERT VIZ] {e}")
            import traceback
            traceback.print_exc()
    
    # ==================== SIMULATION THREAD ====================
    def run_simulation_thread(self, file_path):
        """Run CSV simulation in background thread securely"""
        self.sim_thread_id += 1
        current_id = self.sim_thread_id
        self.sim_active = True

        def sim_loop():
            try:
                df = pd.read_csv(file_path)
                df.columns = df.columns.str.strip()
                
                self.backend.dynamic_layer.csv_buffer = []
                self.backend.network_layer.sim_buffer = []
                self.backend.alerts = []
                
                self.root.after(0, lambda: self.lbl_csv_info.config(
                    text=f"● STREAMING: PARSER Capture", fg=CyberTheme.ACCENT_PURPLE
                ))
                
                for index, row in df.iterrows():
                    # Break immediately if stopped or mode switched to Real-Time
                    if not self.monitoring_active or not self.sim_active or self.sim_thread_id != current_id:
                        break
                    
                    sim_pid = random.randint(1000, 9999)
                    cat_name = row.get('Category', 'Unknown')
                    
                    dyn_result = self.backend.dynamic_layer.inject_single_row(row, sim_pid, cat_name)
                    net_result = self.backend.network_layer.inject_single_row(row, sim_pid)
                    
                    if dyn_result and net_result:
                        is_proc_mal = dyn_result['status'] == "MALICIOUS"
                        is_net_mal = net_result['status'] == "MALICIOUS"
                        
                        if is_proc_mal and is_net_mal:
                            alert = {
                                'timestamp': datetime.now().strftime("%H:%M:%S"),
                                'label': "DATA EXFILTRATION",
                                'confidence': (dyn_result['score'] + net_result['score']) / 2,
                                'reason': f"Spyware '{cat_name}' (PID {sim_pid}) → {net_result['ip']}",
                                'pid': str(sim_pid),
                                'process': cat_name,
                                'ip': net_result['ip']
                            }
                            self.backend.alerts.insert(0, alert)
                    
                    time.sleep(0.5)
                
                if self.sim_thread_id == current_id:
                    self.sim_active = False 
            
            except Exception as e:
                print(f"[SIM ERROR] {e}")
                if self.sim_thread_id == current_id:
                    self.sim_active = False
        
        threading.Thread(target=sim_loop, daemon=True).start()
    
    # ==================== UTILITY FUNCTIONS ====================
    def browse_file(self):
        """Browse for file to scan"""
        path = filedialog.askopenfilename()
        if path:
            self.static_path_var.set(path)
    
    def scan_static_file(self):
        """Scan selected file"""
        path = self.static_path_var.get().strip()
        if not path:
            self.show_warning_dialog("No File", "Please select a file first")
            return
        
        try:
            result = self.backend.scan_static(path)
            
            # Update details tree
            for item in self.static_details_tree.get_children():
                self.static_details_tree.delete(item)
            
            for key, value in result.details.items():
                self.static_details_tree.insert("", END, text=key, values=(str(value),))
            
            self.update_static_history()
            self.log_message(f"[SCAN] {path} → Score: {result.score} ({result.label})")
            
            if result.label == "Malicious":
                self.show_warning_dialog(
                    "⚠ MALICIOUS FILE DETECTED", 
                    f"Risk Score: {result.score}\nRecommendation: Quarantine immediately"
                )
        
        except Exception as e:
            self.show_error_dialog("Scan Error", str(e))
    
    def update_static_history(self):
        """Update scan history table"""
        for item in self.static_history_tree.get_children():
            self.static_history_tree.delete(item)
        
        history = self.backend.static_layer.get_scan_history(20)
        for scan in history:
            filename = os.path.basename(scan['details']['path'])
            self.static_history_tree.insert("", END, values=(
                filename, scan['score'], scan['label']
            ))
    
    def quarantine_file(self):
        """Quarantine suspicious file"""
        path = self.static_path_var.get().strip()
        if not path:
            self.show_warning_dialog("No File", "Please scan a file first")
            return
        
        success, message = self.backend.quarantine_file(path)
        if success:
            self.log_message(f"[QUARANTINE] {path}")
            self.show_info_dialog("Success", message)
            self.static_path_var.set("")
        else:
            self.show_error_dialog("Failed", message)
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.backend.alerts.clear()
        self.update_alerts_view()
        self.update_alert_visualization()
        self.log_message("[SYSTEM] Alerts cleared")
    
    def export_logs(self):
        """Export logs to CSV"""
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        if path:
            success, message = self.backend.export_logs(path)
            if success:
                self.log_message(f"[EXPORT] Logs → {path}")
                self.show_info_dialog("Success", message)
            else:
                self.show_error_dialog("Failed", message)
    
    def train_ml_models(self):
        """Train all ML models"""
        self.train_status_label.config(
            text="◆ TRAINING IN PROGRESS...", 
            fg=CyberTheme.ACCENT_YELLOW
        )
        self.root.update()
        
        def train_thread():
            results = self.backend.train_all_ml_models()
            success_count = sum(1 for success, _ in results.values() if success)
            
            if success_count == 3:
                message = "✓ ALL MODELS TRAINED"
                color = CyberTheme.ACCENT_GREEN
            elif success_count > 0:
                message = f"⚠ {success_count}/3 MODELS TRAINED"
                color = CyberTheme.ACCENT_YELLOW
            else:
                message = "✗ TRAINING FAILED"
                color = CyberTheme.ACCENT_RED
            
            self.root.after(0, lambda: self.train_status_label.config(
                text=message, fg=color
            ))
            self.root.after(0, lambda: self.log_message(f"[ML] {message}"))
            
            details = []
            for layer, (success, msg) in results.items():
                status = "✓" if success else "✗"
                details.append(f"{status} {layer.capitalize()}: {msg}")
            
            self.root.after(0, lambda: self.show_info_dialog(
                "Training Results", "\n".join(details)
            ))
        
        threading.Thread(target=train_thread, daemon=True).start()
    
    def log_message(self, message):
        """Log message to console and UI"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        if hasattr(self, 'log_text'):
            self.log_text.insert(END, log_entry)
            self.log_text.see(END)
        
        print(log_entry.strip())
    
    # ==================== DIALOG HELPERS ====================
    def show_info_dialog(self, title, message):
        """Show info dialog with cyber theme"""
        messagebox.showinfo(title, message)
    
    def show_warning_dialog(self, title, message):
        """Show warning dialog"""
        messagebox.showwarning(title, message)
    
    def show_error_dialog(self, title, message):
        """Show error dialog"""
        messagebox.showerror(title, message)

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