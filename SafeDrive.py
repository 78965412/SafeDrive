#!/usr/bin/env python3

import os
import sys
import shlex
import subprocess
import threading
import logging
import hashlib
import shutil
import time
import re
import signal
import json
from datetime import datetime
from logging.handlers import RotatingFileHandler
import platform
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ttkbootstrap as tb
from ttkbootstrap.constants import *

# Optional preview support
try:
    from PIL import Image, ImageTk
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False

# Optional PDF report support
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.units import mm
    HAVE_REPORTLAB = True
except Exception:
    HAVE_REPORTLAB = False

# ---------------- Config ----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
RECOVERED_BASE = os.path.join(BASE_DIR, "recovered")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
COMMANDS_LOG = os.path.join(LOGS_DIR, "commands.log")
HASHES_FILENAME = "hashes.txt"
MAX_LOG_BYTES = 8 * 1024 * 1024
BACKUP_COUNT = 5

for d in (LOGS_DIR, RECOVERED_BASE, REPORTS_DIR):
    os.makedirs(d, exist_ok=True)

# ---------------- Helpers ----------------
ANSI_RE = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]|\x1b\].*?\x07|\x1b\[K|\x1b\[2J|\x1b\[H|\x1b\[.*?m')
def strip_ansi(s: str) -> str:
    if not s: return s
    return ANSI_RE.sub('', s)

def human_readable(n):
    try:
        n = float(n)
    except:
        return str(n)
    for u in ['B','KB','MB','GB','TB','PB']:
        if abs(n) < 1024.0:
            if u == 'B':
                return f"{int(n)}{u}"
            return f"{n:3.1f}{u}"
        n /= 1024.0
    return f"{n:.1f}EB"

def safe_file_name(s):
    return re.sub(r'[^A-Za-z0-9._-]+', '_', s or '')

def append_command_log(cmd_list):
    try:
        with open(COMMANDS_LOG, 'a', encoding='utf-8') as cf:
            cf.write(f"{datetime.now().isoformat()}  COMMAND: {' '.join(cmd_list)}\n")
    except Exception:
        pass

# ---------------- run subprocess & capture ----------------
def run_command_capture(cmd, update_cb=None, stop_event=None, proc_container=None, env=None, cwd=None, logfile=None):
    try:
        popen_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, cwd=cwd, bufsize=1)
        if os.name != 'nt':
            popen_kwargs['preexec_fn'] = os.setsid
        proc = subprocess.Popen(cmd, **popen_kwargs)
        if proc_container is not None:
            proc_container['proc'] = proc
    except FileNotFoundError:
        msg = f"COMMAND_NOT_FOUND: {cmd[0]}"
        if update_cb: update_cb(msg)
        if logfile:
            try:
                with open(logfile, 'a', encoding='utf-8') as lf: lf.write(f"{datetime.now().isoformat()} {msg}\n")
            except: pass
        return 127
    except Exception as e:
        msg = f"FAILED_TO_LAUNCH: {e}"
        if update_cb: update_cb(msg)
        if logfile:
            try:
                with open(logfile, 'a', encoding='utf-8') as lf: lf.write(f"{datetime.now().isoformat()} {msg}\n")
            except: pass
        return 1

    try:
        while True:
            if stop_event and stop_event.is_set():
                try:
                    if os.name != 'nt':
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                        except Exception:
                            proc.terminate()
                    else:
                        proc.terminate()
                except Exception:
                    pass
                break

            line = proc.stdout.readline()
            if line:
                clean = strip_ansi(line.rstrip('\n'))
                if logfile:
                    try:
                        with open(logfile, 'a', encoding='utf-8') as lf:
                            lf.write(f"{datetime.now().isoformat()} {clean}\n")
                    except: pass
                if update_cb:
                    try: update_cb(clean)
                    except: pass
            elif proc.poll() is not None:
                rest = proc.stdout.read()
                if rest:
                    for l in rest.splitlines():
                        clean = strip_ansi(l.rstrip('\n'))
                        if logfile:
                            try:
                                with open(logfile, 'a', encoding='utf-8') as lf:
                                    lf.write(f"{datetime.now().isoformat()} {clean}\n")
                            except: pass
                        if update_cb:
                            try: update_cb(clean)
                            except: pass
                break
            else:
                time.sleep(0.01)
    except Exception:
        pass

    try:
        rc = proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
            rc = proc.wait(timeout=2)
        except Exception:
            rc = 1
    return rc

# ---------------- GUI logging handler ----------------
class TextWidgetHandler(logging.Handler):
    def __init__(self, widget):
        super().__init__(); self.widget = widget
    def emit(self, record):
        try:
            msg = self.format(record)
            self.widget.after(0, self._append, msg)
        except: pass
    def _append(self, msg):
        try:
            self.widget.config(state=tk.NORMAL)
            self.widget.insert(tk.END, msg + "\n")
            self.widget.see(tk.END)
            self.widget.config(state=tk.DISABLED)
        except: pass

# ---------------- device listing ----------------
def list_block_devices():
    out = []
    try:
        res = subprocess.run(['lsblk','-b','-P','-o','NAME,SIZE,TYPE,MODEL,TRAN,RM'], capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            kv = {}
            for p in line.strip().split():
                if '=' in p:
                    k,v = p.split('=',1); kv[k] = v.strip('"')
            typ = kv.get('TYPE',''); name = kv.get('NAME',''); model = kv.get('MODEL','')
            try: size = int(kv.get('SIZE') or '0')
            except: size = 0
            if typ in ('disk','part'):
                label = f"{('Disk' if typ=='disk' else 'Partition')} - {model or name} — {human_readable(size)}"
                path = f"/dev/{name}"
                out.append((label, path, size, typ))
    except Exception:
        pass
    return out

# ---------------- utility: parent disk ----------------
def get_parent_device(device_path):
    if not device_path:
        return None
    b = os.path.basename(device_path)
    m = re.match(r'^(nvme\d+n\d+)(p\d+)$', b)
    if m:
        return "/dev/" + m.group(1)
    m2 = re.match(r'^([a-z]+)(\d+)$', b)
    if m2:
        return "/dev/" + m2.group(1)
    parent = re.sub(r'\d+$', '', b)
    if parent == b:
        return device_path
    return "/dev/" + parent

def query_device_info(device):
    info = {'name': device or 'Unknown', 'size': 'Unknown', 'fstype': 'Unknown', 'mountpoint': 'Unknown', 'type': 'Unknown', 'tran': 'Unknown', 'model': 'Unknown'}
    if not device:
        return info
    try:
        res = subprocess.run(['lsblk','-P','-o','NAME,SIZE,FSTYPE,MOUNTPOINT,TYPE,TRAN,MODEL', device], capture_output=True, text=True, timeout=3)
        lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
        if lines:
            kv = {}
            for tok in shlex.split(lines[0]):
                if '=' in tok:
                    k,v = tok.split('=',1); kv[k] = v.strip('"')
            info['name'] = kv.get('NAME', info['name'])
            info['size'] = kv.get('SIZE', info['size'])
            info['fstype'] = kv.get('FSTYPE', info['fstype'])
            info['mountpoint'] = kv.get('MOUNTPOINT', info['mountpoint'])
            info['type'] = kv.get('TYPE', info['type'])
            info['tran'] = kv.get('TRAN', info['tran'])
            info['model'] = kv.get('MODEL', info['model'])
    except Exception:
        pass
    return info

# ---------------- Main App ----------------
class SafeDriveApp(tb.Window):
    OMIT_EXTENSIONS = {'dovecot'}  # omit these completely
    def __init__(self):
        super().__init__(themename="flatly")
        self.title("SafeDrive: Data Recovery Toolkit")
        self.geometry("1220x780"); self.minsize(1000,650)

        # state
        self.device_entries = []; self.device_map = {}
        self.selected_path = None; self.selected_label = None; self.selected_size = 0
        self.selected_image = None

        # control
        self.proc_container = {}
        self.operation_thread = None
        self.operation_lock = threading.Lock()
        self.stop_event = threading.Event()

        # pause state
        self._paused = False
        self._pause_lock = threading.Lock()

        # metadata
        self.recovery_root = None; self.restored_dir = None; self.hashes_path = None; self.report_path = None
        self.start_time = None; self.end_time = None

        # command/description
        self.operation_description = None
        self.operation_command_line = None

        # logs
        self.logfile_path = os.path.join(LOGS_DIR, f"safedrive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

        # UI state
        self._tree_selectmode = "extended"
        self.theme_choice = tk.StringVar(value='light')
        self.checkbox_vars = []
        self._rel_to_iid = {}
        self._tb_style = tb.Style()

        # progress accounting (improved)
        self._lock_bytes = threading.Lock()
        self._bytes_recovered = 0            # bytes actually recovered (counting readable non-omitted files)
        self._last_bytes_snapshot = 0
        self._source_size = 0                # bytes of source (device/image) if known

        # animation targets
        self._anim_lock = threading.Lock()
        self._anim_target = None
        self._animating = False

        self._build_ui()
        self._setup_logging()
        self.refresh_devices()
        self._set_idle_ui()
        self._refresh_reports_list()
        self._apply_theme()

    def _build_ui(self):
        top = tb.Frame(self, padding=8); top.pack(fill=tk.X)
        theme_frame = tb.Frame(top); theme_frame.pack(side=tk.LEFT)
        ttk.Label(theme_frame, text="Theme:").pack(side=tk.LEFT, padx=(0,4))
        self.theme_combo = ttk.Combobox(theme_frame, textvariable=self.theme_choice, values=['light','dark'], width=8, state='readonly')
        self.theme_combo.pack(side=tk.LEFT); self.theme_combo.bind('<<ComboboxSelected>>', lambda e: self._on_theme_change())

        tb.Label(top, text="SafeDrive: Data Recovery Toolkit", font=("Helvetica",16,"bold")).pack(side=tk.LEFT, padx=6)

        srcrow = tb.Frame(self, padding=6); srcrow.pack(fill=tk.X)
        tb.Label(srcrow, text="Source:", font=("Helvetica",11)).pack(side=tk.LEFT, padx=(6,4))
        self.src_mode = tk.StringVar(value="Disk")
        self.src_combo = ttk.Combobox(srcrow, textvariable=self.src_mode, values=["Disk","Raw Image"], state='readonly', width=12)
        self.src_combo.pack(side=tk.LEFT, padx=4); self.src_combo.bind("<<ComboboxSelected>>", lambda e: self._on_source_change())

        self.device_var = tk.StringVar()
        self.device_dropdown = ttk.Combobox(srcrow, textvariable=self.device_var, state='readonly', width=74)
        self.device_dropdown.pack(side=tk.LEFT, padx=6); self.device_dropdown.bind("<<ComboboxSelected>>", lambda e: self._on_device_selected())

        self.select_image_btn = tb.Button(srcrow, text="Select Image...", bootstyle="secondary", command=self._choose_image)
        self.select_image_btn.pack_forget()

        tb.Button(srcrow, text="Refresh", bootstyle="info", command=self.refresh_devices).pack(side=tk.LEFT, padx=6)
        tb.Button(srcrow, text="Disk Info", bootstyle="secondary", command=self._open_disk_info).pack(side=tk.LEFT, padx=6)

        ops = tb.Frame(self, padding=6); ops.pack(fill=tk.Y)
        self.recover_btn = tb.Button(ops, text="Recover Deleted Files", bootstyle="primary", width=30, command=self._start_recovery)
        self.recover_btn.pack(side=tk.LEFT, padx=8)
        self.stop_btn = tb.Button(ops, text="Stop", bootstyle="danger", width=12, command=self._stop_recovery)
        self.stop_btn.pack(side=tk.LEFT, padx=6)
        self.pause_btn = tb.Button(ops, text="Pause", bootstyle="warning", width=10, command=self._toggle_pause)
        self.pause_btn.pack(side=tk.LEFT, padx=6)
        self.save_btn = tb.Button(ops, text="Save All Recovered To...", bootstyle="secondary", width=25, command=self._save_recovered)
        self.save_btn.pack(side=tk.LEFT, padx=6)

        prog = tb.Frame(self, padding=6); prog.pack(fill=tk.X, padx=10)
        # Green indicator label for recovery mode
        self.mode_indicator = tk.Label(prog, text="IDLE", bg="#D0D0D0", fg="#000", font=("Helvetica",10,"bold"), padx=8, pady=4)
        self.mode_indicator.pack(side=tk.LEFT, padx=(6,8))
        self.status_var = tk.StringVar(value=""); tb.Label(prog, textvariable=self.status_var, bootstyle="secondary").pack(side=tk.LEFT, padx=6)

        # create progressbar styles for running and paused states
        s = ttk.Style()
        # style names
        self._pb_style_running = "green.Horizontal.TProgressbar"
        self._pb_style_paused = "red.Horizontal.TProgressbar"
        # configure styles (note: some ttk themes ignore troughcolor; works on many linux setups)
        try:
            s.configure(self._pb_style_running, troughcolor='#e9f7ef', background='#2ecc71')
            s.configure(self._pb_style_paused, troughcolor='#fdecea', background='#e74c3c')
        except Exception:
            pass

        # progress bar + percent
        self.progress = ttk.Progressbar(prog, orient=tk.HORIZONTAL, mode='determinate', length=700, style=self._pb_style_running)
        self.progress.pack(side=tk.LEFT, fill=tk.X, padx=8, pady=6, expand=True)
        self.percent_lbl = tb.Label(prog, text="0%", font=("Helvetica",10,"bold")); self.percent_lbl.pack(side=tk.RIGHT, padx=8)

        # main panes and tree/checkbox areas (unchanged structure)
        paned = ttk.Panedwindow(self, orient=tk.HORIZONTAL); paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        left = tb.Frame(paned, padding=6); right = tb.Frame(paned, padding=6); paned.add(left, weight=1); paned.add(right, weight=1)

        rec_frame = tb.LabelFrame(left, text="Recovered Files (Present & Recovered)", padding=6, bootstyle="light")
        rec_frame.pack(fill=tk.BOTH, expand=True)
        self.recovery_label = tb.Label(rec_frame, text="Recovery root: (none)", bootstyle="secondary")
        self.recovery_label.pack(fill=tk.X, padx=4, pady=4)
        self.recovery_label.bind("<Button-3>", self._on_recovery_label_right_click)

        self.tree = ttk.Treeview(rec_frame, columns=("size","type"), show='tree headings', selectmode='extended')
        self.tree.heading("#0", text="Name"); self.tree.heading("size", text="Size"); self.tree.heading("type", text="Type")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.tree.bind("<Double-1>", lambda e: self._open_selected()); self.tree.bind("<Button-3>", self._on_right_click_menu)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._on_tree_selection_changed())

        selection_label = ttk.Label(rec_frame, text="Select files or folders to recover (checkboxes below):", font=("Helvetica",10,"bold"))
        selection_label.pack(fill=tk.X, padx=4, pady=(6,2))
        cb_container = ttk.Frame(rec_frame)
        cb_container.pack(fill=tk.BOTH, expand=False, padx=4, pady=(0,6))

        search_row = ttk.Frame(rec_frame)
        search_row.pack(fill=tk.X, padx=4, pady=(0,4))
        ttk.Label(search_row, text="Filter:").pack(side=tk.LEFT, padx=(0,6))
        self.cb_search_var = tk.StringVar()
        self.cb_search_entry = ttk.Entry(search_row, textvariable=self.cb_search_var)
        self.cb_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.cb_search_entry.bind("<KeyRelease>", lambda e: self._filter_checkboxes())

        self._cb_canvas = tk.Canvas(cb_container, height=180)
        self._cb_scroll = ttk.Scrollbar(cb_container, orient="vertical", command=self._cb_canvas.yview)
        self._cb_frame = ttk.Frame(self._cb_canvas)
        self._cb_frame_id = self._cb_canvas.create_window((0,0), window=self._cb_frame, anchor='nw')
        self._cb_canvas.configure(yscrollcommand=self._cb_scroll.set)
        self._cb_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._cb_scroll.pack(side=tk.RIGHT, fill=tk.Y)  
        self._cb_frame.bind("<Configure>", lambda e: self._cb_canvas.configure(scrollregion=self._cb_canvas.bbox("all")))

        tree_btns = tb.Frame(rec_frame, padding=6); tree_btns.pack(fill=tk.X)
        tb.Button(tree_btns, text="Recover Selected", bootstyle="success", command=self._recover_selected).pack(side=tk.LEFT, padx=6)
        tb.Button(tree_btns, text="Delete Recovered Files", bootstyle="danger", command=self._delete_recovered).pack(side=tk.RIGHT, padx=6)

        cb_actions = tb.Frame(rec_frame, padding=6); cb_actions.pack(fill=tk.X)
        self.checked_count_var = tk.IntVar(value=0)
        ttk.Label(cb_actions, text="Checked:").pack(side=tk.LEFT, padx=(4,6))
        ttk.Label(cb_actions, textvariable=self.checked_count_var, width=6).pack(side=tk.LEFT)
        ttk.Button(cb_actions, text="Select All", command=self._check_all).pack(side=tk.LEFT, padx=6)
        ttk.Button(cb_actions, text="Clear All", command=self._uncheck_all).pack(side=tk.LEFT, padx=6)

        log_ctrl = tb.Frame(right, padding=6); log_ctrl.pack(fill=tk.X)
        self.reports_var = tk.StringVar()
        self.reports_combo = ttk.Combobox(log_ctrl, textvariable=self.reports_var, values=[], state='readonly', width=48)
        self.reports_combo.pack(side=tk.LEFT, padx=(2,6))
        self.view_report_btn = tb.Button(log_ctrl, text="Open Report", bootstyle="secondary", command=self._open_selected_report)
        self.view_report_btn.pack(side=tk.LEFT, padx=6)
        self.download_report_btn = tb.Button(log_ctrl, text="Download Report...", bootstyle="outline-secondary", command=self._download_selected_report)
        self.download_report_btn.pack(side=tk.LEFT, padx=6)
        tb.Button(log_ctrl, text="Open Log File", bootstyle="secondary", command=self._open_log_file).pack(side=tk.LEFT, padx=6)
        tb.Button(log_ctrl, text="Clear Log View", bootstyle="outline-secondary", command=self._clear_log_view).pack(side=tk.LEFT, padx=6)

        log_frame = tb.LabelFrame(right, text="Log Terminal", padding=6); log_frame.pack(fill=tk.BOTH, expand=True)
        self.log_text = tk.Text(log_frame, state=tk.DISABLED, font=("Consolas",10)); self.log_text.pack(fill=tk.BOTH, expand=True)

    def _on_theme_change(self):
        choice = (self.theme_choice.get() or 'light').lower()
        if choice == 'dark':
            try: self._tb_style.theme_use('darkly')
            except: pass
        else:
            try: self._tb_style.theme_use('flatly')
            except: pass
        self._apply_theme()

    def _apply_theme(self):
        choice = (self.theme_choice.get() or 'light').lower()
        if choice == 'dark':
            fg = '#FFFFFF'; bg = '#1e1e1e'; frame_bg = '#222222'; entry_bg = '#2b2b2b'; alt_bg = '#2a2a2a'; text_bg = '#111111'; tree_bg = '#111111'
        else:
            fg = '#000000'; bg = '#F8FAFC'; frame_bg = '#FFFFFF'; entry_bg = '#FFFFFF'; alt_bg = '#F4F6F8'; text_bg = '#FFFFFF'; tree_bg = '#FFFFFF'
        try: self.configure(bg=bg)
        except: pass
        s = ttk.Style()
        try:
            s.configure('.', background=frame_bg)
            s.configure('TLabel', foreground=fg, background=frame_bg)
            s.configure('TEntry', foreground=fg, fieldbackground=entry_bg)
            s.configure('Treeview', foreground=fg, background=tree_bg, fieldbackground=tree_bg)
            s.configure('Treeview.Heading', foreground=fg, background=alt_bg)
        except: pass

        def walk_and_apply(w):
            try:
                if isinstance(w, tk.Text):
                    try: w.configure(bg=text_bg, fg=fg, insertbackground=fg)
                    except: pass
                if isinstance(w, tk.Canvas):
                    try: w.configure(bg=frame_bg, highlightthickness=0)
                    except: pass
                if isinstance(w, tk.Checkbutton):
                    try: w.configure(fg=fg, bg=frame_bg, activeforeground=fg, selectcolor=frame_bg)
                    except: pass
                if isinstance(w, tk.Label) and not isinstance(w, ttk.Label):
                    try: w.configure(bg=frame_bg, fg=fg)
                    except: pass
                if isinstance(w, tk.Entry):
                    try: w.configure(bg=entry_bg, fg=fg, insertbackground=fg)
                    except: pass
                if isinstance(w, tk.Frame) and not isinstance(w, ttk.Frame):
                    try: w.configure(bg=frame_bg)
                    except: pass
                if isinstance(w, tk.Button):
                    try: w.configure(bg=alt_bg, fg=fg, activebackground=frame_bg)
                    except: pass
                if isinstance(w, ttk.Treeview):
                    try:
                        w.configure(selectbackground=alt_bg, selectforeground=fg)
                    except: pass
            except Exception:
                pass
            for child in w.winfo_children():
                walk_and_apply(child)
        walk_and_apply(self)

        try:
            for var, full, rel, cb in self.checkbox_vars:
                try:
                    cb.configure(fg=fg, bg=frame_bg, selectcolor=frame_bg, activeforeground=fg)
                except:
                    pass
        except Exception:
            pass

        try:
            self.tree.tag_configure('oddrow', background=alt_bg, foreground=fg)
            self.tree.tag_configure('evenrow', background=frame_bg, foreground=fg)
        except Exception:
            pass

    def _setup_logging(self):
        self.file_logger = logging.getLogger("safedrive_file"); self.file_logger.setLevel(logging.INFO)
        if self.file_logger.handlers: self.file_logger.handlers.clear()
        fh = RotatingFileHandler(self.logfile_path, maxBytes=MAX_LOG_BYTES, backupCount=BACKUP_COUNT)
        fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")); self.file_logger.addHandler(fh)
        self.file_logger.info("SafeDrive started")

        self.gui_logger = logging.getLogger("safedrive_gui"); self.gui_logger.setLevel(logging.INFO)
        if self.gui_logger.handlers: self.gui_logger.handlers.clear()
        th = TextWidgetHandler(self.log_text); th.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")); self.gui_logger.addHandler(th)
        self.gui_logger.info("SafeDrive started (GUI)")

    def log(self, msg, level=logging.INFO):
        try: self.file_logger.log(level, msg)
        except: pass
        masked = re.sub(r'\b(photorec|dd|dcfldd|gddrescue|testdisk|stdbuf)\b','[tool]', msg, flags=re.I)
        try: self.gui_logger.log(level, masked)
        except: pass

    # ---------------- devices ----------------
    def refresh_devices(self):
        try:
            self.progress['value'] = 0
            self.percent_lbl.config(text="0%")
            self.status_var.set("")
        except:
            pass

        devs = list_block_devices()
        self.device_entries = devs
        self.device_map.clear()
        labels = []
        for label, path, size, typ in devs:
            labels.append(label)
            self.device_map[label] = (path, size, typ)
        self.device_dropdown['values'] = labels

        prev_label = self.device_var.get() if hasattr(self, 'device_var') else None
        prev_path = getattr(self, 'selected_path', None)
        chosen_index = None

        if prev_label and prev_label in labels:
            try:
                chosen_index = labels.index(prev_label)
            except Exception:
                chosen_index = None
        if chosen_index is None and prev_path:
            for i, lbl in enumerate(labels):
                p, s, t = self.device_map.get(lbl, (None, 0, None))
                if p == prev_path:
                    chosen_index = i
                    break

        if chosen_index is not None:
            try:
                self.device_dropdown.current(chosen_index)
                self._on_device_selected()
            except Exception:
                pass
        else:
            self.device_var.set("")
            self.selected_label = None
            self.selected_path = None
            self.selected_size = 0

        self.log(f"{len(labels)} device(s)/partition(s) detected")

    def _on_source_change(self):
        if self.src_mode.get() == "Disk":
            self.device_dropdown.configure(state='readonly')
            try:
                self.select_image_btn.pack_forget()
            except:
                pass
        else:
            self.device_dropdown.configure(state='disabled')
            try:
                self.select_image_btn.pack(side=tk.LEFT, padx=6)
            except:
                pass

    def _on_device_selected(self):
        label = self.device_var.get()
        if not label:
            self.selected_label = None
            self.selected_path = None
            self.selected_size = 0
            return
        p, s, typ = self.device_map.get(label, (None, 0, None))
        self.selected_label = label
        self.selected_path = p
        self.selected_size = s
        self.log(f"Selected: {label} (path hidden)")

    def _choose_image(self):
        f = filedialog.askopenfilename(
            title="Select raw image",
            filetypes=[("Raw images", "*.img *.dd *.raw *.ddns *.001"), ("All files", "*.*")]
        )
        if not f:
            return
        self.selected_image = f
        try:
            self.selected_size = os.path.getsize(f)
        except:
            self.selected_size = 0
        display = f"Image - {os.path.basename(f)} — {human_readable(self.selected_size)}"
        vals = list(self.device_dropdown['values'])
        if display not in vals:
            vals.insert(0, display)
            self.device_dropdown['values'] = vals
        self.device_dropdown.current(0)
        self.selected_label = display
        self.selected_path = self.selected_image
        self.log(f"Selected raw image: {f}")

    def _open_disk_info(self):
        if self.src_mode.get() == "Disk":
            if not self.selected_path:
                messagebox.showerror("Select","Choose disk"); return
            target = self.selected_path
        else:
            if not getattr(self, 'selected_image', None):
                messagebox.showerror("Select","Choose image"); return
            target = self.selected_image
        info = ""
        try:
            if os.path.isfile(target):
                info += f"Image: {target}\nSize: {human_readable(os.path.getsize(target))}\n\n"
            else:
                p = subprocess.run(['lsblk','-o','NAME,SIZE,FSTYPE,MOUNTPOINT,MODEL', target], capture_output=True, text=True, timeout=6)
                info += p.stdout + "\n\n"
        except:
            info += "Device listing unavailable\n\n"
        if shutil.which('smartctl'):
            try:
                p = subprocess.run(['smartctl','-H', target], capture_output=True, text=True, timeout=6)
                info += "SMART:\n" + "\n".join(p.stdout.splitlines()[:8]) + "\n"
            except:
                info += "SMART: error\n"
        else:
            info += "SMART not available\n"
        try:
            p = subprocess.run(['parted','-s', target, 'print'], capture_output=True, text=True, timeout=6)
            if p.returncode == 0 and p.stdout.strip(): info += "\nPartition Info:\n" + p.stdout
        except: pass
        win = tk.Toplevel(self); win.title("Disk Info"); win.geometry("700x500")
        txt = tk.Text(win, wrap=tk.WORD, font=("Consolas",10)); txt.pack(fill=tk.BOTH, expand=True); txt.insert(tk.END, info); txt.config(state=tk.DISABLED)

    # ---------------- present data collection ----------------
    def _collect_present_data(self):
        if not self.recovery_root:
            return
        try:
            device = self.selected_path
            info = query_device_info(device)
            mount = info.get('mountpoint') or ''
            if not mount or not os.path.isdir(mount):
                parent = get_parent_device(device) if device else None
                pinfo = query_device_info(parent) if parent else {}
                mount = pinfo.get('mountpoint') or ''
            if not mount or not os.path.isdir(mount):
                self.log("No mountpoint found for selected device; skipping present_data collection")
                return
            present_dir = os.path.join(self.recovery_root, "present_data")
            os.makedirs(present_dir, exist_ok=True)
            for entry in os.listdir(mount):
                src = os.path.join(mount, entry)
                dst = os.path.join(present_dir, entry)
                try:
                    if os.path.isdir(src):
                        shutil.copytree(src, dst, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src, dst)
                except Exception as e:
                    self.file_logger.warning(f"Failed to copy present data {src} -> {dst}: {e}")
            self.log(f"Present data copied from mountpoint '{mount}' to '{present_dir}'")
        except Exception as e:
            self.file_logger.warning(f"Present data collection failed: {e}")

    # ---------------- recovery orchestration ----------------
    def _start_recovery(self):
        if self.src_mode.get() == "Disk":
            if not self.selected_path:
                messagebox.showerror("Select","Choose disk/partition first"); return
            source = self.selected_path; source_label = self.selected_label; source_size = self.selected_size
        else:
            if not getattr(self, 'selected_image', None):
                messagebox.showerror("Select","Choose raw image"); return
            source = self.selected_image; source_label = os.path.basename(self.selected_image)
            try: source_size = os.path.getsize(self.selected_image)
            except: source_size = 0

        with self.operation_lock:
            if self.operation_thread and self.operation_thread.is_alive():
                messagebox.showwarning("Busy","Another operation is running"); return

            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.recovery_root = os.path.join(RECOVERED_BASE, ts)
            self.restored_dir = os.path.join(self.recovery_root, "restored_data")
            os.makedirs(self.restored_dir, exist_ok=True)
            self.hashes_path = os.path.join(self.recovery_root, HASHES_FILENAME)
            self.report_path = os.path.join(REPORTS_DIR, f"report_{ts}.pdf")
            self.recovery_label.config(text=f"Recovery root: {self.recovery_root}")
            self.log(f"Prepared recovery root for {source_label}")

            try:
                self._collect_present_data()
            except Exception:
                pass

            self.progress['value'] = 0; self.percent_lbl.config(text="0%"); self.status_var.set("")
            self.stop_event.clear(); self.proc_container.clear()
            self.start_time = datetime.now(); self.end_time = None

            # set source size for progress accounting
            self._source_size = source_size or 0
            with self._lock_bytes:
                self._bytes_recovered = 0
                self._last_bytes_snapshot = 0

            if not shutil.which('photorec'):
                messagebox.showerror("Missing","photorec not found (install testdisk)")
                self.log("photorec missing", level=logging.ERROR); return

            base = ['photorec', '/log', '/d', self.restored_dir, '/cmd', source]
            options = ['fileopt', 'everything', 'enable', 'search']
            variants = [
                ','.join(options),
                ' '.join(options),
                'partition_none,' + ','.join(options),
                'partition_none ' + ' '.join(options),
                'free,search',
                'free search'
            ]
            chosen = None
            for v in variants:
                cmd = base + [v]
                append_command_log(cmd); self.file_logger.info("EXEC_CMD: " + ' '.join(cmd))
                rc_probe, probe_lines = self._probe_cmd(cmd, timeout=1.2)
                joined = "\n".join(probe_lines).lower()
                if "syntax error" in joined or "unable to open file or device" in joined or "select a media" in joined:
                    self.log(f"Variant rejected (probe): {v}", level=logging.INFO)
                    continue
                chosen = cmd; break
            if not chosen:
                chosen = base + ['free,search']; append_command_log(chosen); self.file_logger.info("EXEC_CMD: " + ' '.join(chosen)); self.log("Falling back to variant: free,search")

            stdbuf_path = shutil.which('stdbuf')
            final_cmd = ([stdbuf_path, '-o', 'L'] + chosen) if stdbuf_path else chosen

            try:
                self.operation_command_line = ' '.join(final_cmd)
            except Exception:
                self.operation_command_line = None
            self.operation_description = f"PhotoRec scan"

            self.log("Final photorec command chosen (full command in commands.log).")
            append_command_log(final_cmd); self.file_logger.info("EXEC_CMD_FINAL: " + ' '.join(final_cmd))

            # set UI: indicate recovering (green)
            self._set_mode_indicator("RECOVERING")
            self._set_progress_style_running(True)
            self.status_var.set("Running recovery...")

            # ensure paused state is clear
            with self._pause_lock:
                self._paused = False
                self.pause_btn.configure(text="Pause", bootstyle="warning")

            # start worker
            t = threading.Thread(target=self._run_photorec_scan, args=(final_cmd, source, source_size), daemon=True)
            self.operation_thread = t; t.start()
            self._set_running_ui()

    def _probe_cmd(self, cmd, timeout=2.0):
        lines = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except FileNotFoundError:
            return 127, ["command not found"]
        except Exception as e:
            return 1, [str(e)]
        start = time.time()
        try:
            while time.time() - start < timeout:
                line = proc.stdout.readline()
                if line:
                    lines.append(strip_ansi(line.rstrip('\n')))
                elif proc.poll() is not None:
                    break
                time.sleep(0.01)
            try: proc.terminate()
            except: pass
            try: proc.wait(timeout=1)
            except:
                try: proc.kill()
                except: pass
        except: pass
        rc = proc.returncode if proc.returncode is not None else 0
        return rc, lines

    # animate progress bar toward a target percentage (smoothly)
    def _animate_progress_to(self, target_pct):
        # target_pct in [0,100]
        try:
            with self._anim_lock:
                self._anim_target = max(0.0, min(100.0, float(target_pct or 0.0)))
                if self._animating:
                    return
                self._animating = True

            def step():
                try:
                    with self._anim_lock:
                        target = self._anim_target
                    cur = float(self.progress['value'] or 0.0)
                    if cur >= target - 0.2:
                        # close enough
                        self.progress['value'] = target
                        self.percent_lbl.config(text=f"{int(round(target))}%")
                        self._animating = False
                        return
                    # step size depends on gap (larger gaps move faster, but capped)
                    gap = target - cur
                    step_size = max(0.2, min(2.5, gap * 0.12))  # tune these values for smoothness
                    new = cur + step_size
                    self.progress['value'] = new
                    self.percent_lbl.config(text=f"{int(round(new))}%")
                    # update status line
                    if self.mode_indicator['text'] == "RECOVERING":
                        self.status_var.set(f"Running recovery — {int(round(new))}%")
                    elif self.mode_indicator['text'] == "PAUSED":
                        self.status_var.set(f"Paused — {int(round(new))}%")
                    else:
                        self.status_var.set("")
                    # schedule next step
                    self.after(120, step)
                except Exception:
                    try:
                        self._animating = False
                    except: pass
            # start stepping
            self.after(40, step)
        except Exception:
            pass

    def _set_progress_target_from_worker(self, pct):
        # called by background threads to request progress change -> animate toward it
        try:
            pct = max(0.0, min(100.0, float(pct or 0.0)))
            # don't jump to 100 until cleaned up; keep worker's cap of 99 until finalization
            if pct > 99.0 and self.operation_thread and self.operation_thread.is_alive():
                pct = 99.0
            self._animate_progress_to(pct)
        except Exception:
            pass

    def _set_progress(self, pct, status_text):
     try:
        pct = max(0.0, min(100.0, float(pct or 0.0)))
        # set immediate target (this will animate)
        self._animate_progress_to(pct)
        if status_text:
            self.status_var.set(status_text)
        else:
            if self.mode_indicator['text'] == "RECOVERING":
                self.status_var.set(f"Running recovery — {int(pct)}%")
            elif self.mode_indicator['text'] == "PAUSED":
                self.status_var.set(f"Paused — {int(pct)}%")
            else:
                self.status_var.set("")
     except:
        pass

    def _set_running_ui(self):
        try:
            try: self.recover_btn.configure(state='disabled')
            except: pass
            try: self.save_btn.configure(state='disabled')
            except: pass
            try: self.view_report_btn.configure(state='disabled')
            except: pass
            try: self.device_dropdown.configure(state='disabled')
            except: pass
            try: self.src_combo.configure(state='disabled')
            except: pass
            try:
                self._tree_selectmode = self.tree.cget('selectmode')
                self.tree.configure(selectmode='none')
            except: pass
            try:
                self.stop_btn.configure(state='normal')
            except: pass
            try:
                self.pause_btn.configure(state='normal')
            except: pass
        except: pass

    def _set_idle_ui(self):
        try:
            try: self.recover_btn.configure(state='normal')
            except: pass
            try: self.save_btn.configure(state='normal')
            except: pass
            try: self.device_dropdown.configure(state='readonly' if self.src_mode.get()=="Disk" else 'disabled')
            except: pass
            try: self.src_combo.configure(state='readonly')
            except: pass
            try:
                self.tree.configure(selectmode=self._tree_selectmode or 'extended')
            except: pass
            try: self.stop_btn.configure(state='disabled')
            except: pass
            try: self.pause_btn.configure(state='disabled')
            except: pass
        except: pass

    def _stop_recovery(self):
        with self.operation_lock:
            if not (self.operation_thread and self.operation_thread.is_alive()):
                messagebox.showinfo("No operation","No recovery running"); return
            confirm = messagebox.askyesno("Stop","Stop running recovery?")
            if not confirm: return

            self.stop_event.set()

            proc = self.proc_container.get('proc')
            if proc:
                try:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except Exception:
                        proc.terminate()
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

            self.log("Stop requested by user; attempting to terminate background tool", level=logging.WARNING)

            def waiter(t):
                try:
                    t.join(timeout=10)
                except Exception:
                    pass

                if t.is_alive():
                    p2 = self.proc_container.get('proc')
                    if p2:
                        try:
                            try:
                                os.killpg(os.getpgid(p2.pid), signal.SIGKILL)
                            except Exception:
                                p2.kill()
                        except Exception:
                            pass
                    try:
                        t.join(timeout=2)
                    except Exception:
                        pass

                try:
                    self.proc_container.clear()
                except Exception:
                    pass
                try:
                    self.stop_event.clear()
                except Exception:
                    pass

                with self.operation_lock:
                    if self.operation_thread is t:
                        self.operation_thread = None

                self._set_idle_ui()
                self._set_mode_indicator("IDLE")
                self._set_progress_style_running(False)
                self.log("Operation stopped; application remains open and ready", level=logging.INFO)

            threading.Thread(target=waiter, args=(self.operation_thread,), daemon=True).start()

    def _toggle_pause(self):
        # toggles pause/resume of the external photorec process (UNIX only)
        with self._pause_lock:
            if not (self.operation_thread and self.operation_thread.is_alive()):
                return
            proc = self.proc_container.get('proc')
            if not proc:
                return
            if not self._paused:
                # request pause
                try:
                    if os.name != 'nt':
                        os.killpg(os.getpgid(proc.pid), signal.SIGSTOP)
                    else:
                        # windows: cannot SIGSTOP; just set indicator and leave process running
                        pass
                    self._paused = True
                    self.pause_btn.configure(text="Resume", bootstyle="success")
                    self._set_mode_indicator("PAUSED")
                    self._set_progress_style_running(False)
                    self.status_var.set(f"Paused — {int(round(float(self.progress['value'] or 0)))}%")
                    self.log("User paused scan (SIGSTOP sent)", level=logging.INFO)
                except Exception as e:
                    self.log(f"Failed to pause process: {e}", level=logging.WARNING)
            else:
                # resume
                try:
                    if os.name != 'nt':
                        os.killpg(os.getpgid(proc.pid), signal.SIGCONT)
                    else:
                        pass
                    self._paused = False
                    self.pause_btn.configure(text="Pause", bootstyle="warning")
                    self._set_mode_indicator("RECOVERING")
                    self._set_progress_style_running(True)
                    self.status_var.set(f"Running recovery — {int(round(float(self.progress['value'] or 0)))}%")
                    self.log("User resumed scan (SIGCONT sent)", level=logging.INFO)
                except Exception as e:
                    self.log(f"Failed to resume process: {e}", level=logging.WARNING)

    def _set_mode_indicator(self, mode):
        try:
            if mode == "RECOVERING":
                self.mode_indicator.config(text="RECOVERING", bg="#1abc9c", fg="#042e2b")
            elif mode == "PAUSED":
                self.mode_indicator.config(text="PAUSED", bg="#e74c3c", fg="#fff")
            else:
                self.mode_indicator.config(text="IDLE", bg="#D0D0D0", fg="#000")
        except: pass

    def _set_progress_style_running(self, running: bool):
        try:
            if running:
                self.progress.configure(style=self._pb_style_running)
            else:
                self.progress.configure(style=self._pb_style_paused)
        except: pass

    # ---------------- organize & populate ----------------
    def _organize_by_extension(self):
        if not self.recovery_root or not os.path.exists(self.recovery_root): return
        final_root = os.path.join(self.recovery_root, "by_extension"); os.makedirs(final_root, exist_ok=True)
        processed = 0
        for root, _, files in os.walk(self.recovery_root):
            for fn in files:
                src = os.path.join(root, fn)
                if os.path.commonpath([final_root, src]) == final_root:
                    continue
                if fn.lower().endswith('.dovecot') or os.path.splitext(fn)[1].lstrip('.').lower() in self.OMIT_EXTENSIONS:
                    try: os.remove(src)
                    except: pass
                    continue
                if not os.access(src, os.R_OK):
                    try: os.remove(src)
                    except: pass
                    continue
                ext = os.path.splitext(fn)[1].lstrip('.').lower() or 'none'
                dest_dir = os.path.join(final_root, ext)
                os.makedirs(dest_dir, exist_ok=True)
                dest = os.path.join(dest_dir, fn)
                if os.path.exists(dest):
                    base, e = os.path.splitext(fn)
                    
                try:
                    shutil.move(src, dest); processed += 1
                except Exception:
                    try:
                        shutil.copy2(src, dest); os.remove(src); processed += 1
                    except Exception as ex:
                        self.file_logger.warning(f"Failed to move/copy {src} -> {dest}: {ex}")
        try:
            for root, dirs, files in os.walk(self.recovery_root, topdown=False):
                try:
                    if not dirs and not files and root != final_root:
                        os.rmdir(root)
                except: pass
        except: pass
        self.restored_dir = final_root
        self.file_logger.info(f"Organized recovered files by extension. Processed {processed} files.")

    def _populate_tree_with_present_and_recovered(self):
        # identical to original implementation (kept for brevity)
        self.tree.delete(*self.tree.get_children())
        self._rel_to_iid.clear()

        present_root = os.path.join(self.recovery_root, "present_data")
        if os.path.exists(present_root):
            pid = self.tree.insert("", tk.END, text="Present Data", open=True, values=("", "folder"))
            self._rel_to_iid["present_data"] = pid
            def insert_present(parent_iid, folder):
                try:
                    entries = sorted(os.listdir(folder))
                except:
                    entries = []
                for e in entries:
                    full = os.path.join(folder, e)
                    rel = os.path.relpath(full, present_root)
                    if os.path.isdir(full):
                        iid = self.tree.insert(parent_iid, tk.END, text=e, open=False, values=("", "folder"))
                        self._rel_to_iid[os.path.join("present_data", rel)] = iid
                        insert_present(iid, full)
                    else:
                        try:
                            sz = human_readable(os.path.getsize(full))
                        except:
                            sz = '?'
                        iid = self.tree.insert(parent_iid, tk.END, text=e, values=(sz, os.path.splitext(e)[1].lstrip('.') or 'file'))
                        self._rel_to_iid[os.path.join("present_data", rel)] = iid
            insert_present(pid, present_root)

        recovered_root = self.restored_dir or ""
        if recovered_root and os.path.exists(recovered_root):
            rid = self.tree.insert("", tk.END, text="Recovered Data", open=True, values=("", "folder"))
            self._rel_to_iid["recovered_data"] = rid
            def insert_recovered(parent_iid, folder, prefix=""):
                try:
                    entries = sorted(os.listdir(folder))
                except:
                    entries = []
                for e in entries:
                    full = os.path.join(folder, e)
                    rel = os.path.join(prefix, e) if prefix else e
                    if os.path.isdir(full):
                        iid = self.tree.insert(parent_iid, tk.END, text=e, open=False, values=("", "folder"))
                        self._rel_to_iid[rel] = iid
                        insert_recovered(iid, full, rel)
                    else:
                        if not os.access(full, os.R_OK):
                            continue
                        if e.lower().endswith('.dovecot') or os.path.splitext(e)[1].lstrip('.').lower() in self.OMIT_EXTENSIONS:
                            continue
                        try:
                            sz = human_readable(os.path.getsize(full))
                        except:
                            sz = '?'
                        iid = self.tree.insert(parent_iid, tk.END, text=e, values=(sz, os.path.splitext(e)[1].lstrip('.') or 'file'))
                        self._rel_to_iid[rel] = iid
            insert_recovered(rid, recovered_root, "")
        self.tree.update_idletasks()

    def _populate_checkbox_list(self):
        self._clear_checkbox_list()
        base_present = os.path.join(self.recovery_root, "present_data")
        base_recovered = self.restored_dir
        files = []
        if os.path.exists(base_present):
            for root, _, filenames in os.walk(base_present):
                for fn in filenames:
                    full = os.path.join(root, fn)
                    rel = os.path.relpath(full, base_present)
                    if not os.access(full, os.R_OK): continue
                    files.append((os.path.join("present_data", rel), full))
        if base_recovered and os.path.exists(base_recovered):
            for root, _, filenames in os.walk(base_recovered):
                for fn in filenames:
                    if fn.lower().endswith('.dovecot'): continue
                    full = os.path.join(root, fn)
                    rel = os.path.relpath(full, base_recovered)
                    if not os.access(full, os.R_OK): continue
                    files.append((rel, full))
        files.sort(key=lambda x: x[0])
        for rel, full in files:
            var = tk.BooleanVar(value=False)
            disp = rel
            depth = rel.count(os.sep)
            cb = tk.Checkbutton(self._cb_frame, text=disp, variable=var, anchor='w', justify='left', wraplength=900)
            cb.pack(fill=tk.X, anchor='w', padx=(10*depth, 2), pady=1)
            def make_var_trace(v, r):
                def on_change(*args):
                    cnt = sum(1 for vv,_,_,_ in self.checkbox_vars if vv.get())
                    self.checked_count_var.set(cnt)
                    iid = self._rel_to_iid.get(r) or self._rel_to_iid.get(os.path.join("present_data", r))
                    if iid:
                        try:
                            cur = list(self.tree.selection())
                            if v.get():
                                if iid not in cur:
                                    cur.append(iid)
                                    self.tree.selection_set(cur)
                            else:
                                if iid in cur:
                                    cur.remove(iid)
                                    self.tree.selection_set(cur)
                        except Exception:
                            pass
                return on_change
            var.trace_add("write", make_var_trace(var, rel))
            self.checkbox_vars.append((var, full, rel, cb))
        try:
            self._cb_canvas.configure(scrollregion=self._cb_canvas.bbox("all"))
        except Exception:
            pass
        self._filter_checkboxes()
        self._apply_theme()

    def _clear_checkbox_list(self):
        try:
            for w in getattr(self, "_cb_frame").winfo_children():
                try: w.destroy()
                except: pass
        except Exception:
            pass
        self.checkbox_vars = []
        self.checked_count_var.set(0)

    def _filter_checkboxes(self):
        q = (self.cb_search_var.get() or "").strip().lower()
        for var, full, rel, cb in self.checkbox_vars:
            if not q or q in rel.lower():
                try:
                    cb.pack_forget()
                    depth = rel.count(os.sep)
                    cb.pack(fill=tk.X, anchor='w', padx=(10*depth,2), pady=1)
                except Exception:
                    pass
            else:
                try:
                    cb.pack_forget()
                except Exception:
                    pass
        try:
            self._cb_canvas.configure(scrollregion=self._cb_canvas.bbox("all"))
        except Exception:
            pass

    def _check_all(self):
        for var,_,_,_ in self.checkbox_vars:
            var.set(True)
        self.checked_count_var.set(len(self.checkbox_vars))

    def _uncheck_all(self):
        for var,_,_,_ in self.checkbox_vars:
            var.set(False)
        self.checked_count_var.set(0)

    def _on_tree_selection_changed(self):
        selected = set(self.tree.selection())
        for var, full, rel, cb in self.checkbox_vars:
            iid = self._rel_to_iid.get(rel) or self._rel_to_iid.get(os.path.join("present_data", rel))
            should_check = False
            if iid and iid in selected:
                should_check = True
            else:
                parts = rel.split(os.sep)
                cur = ""
                for p in parts[:-1]:
                    cur = os.path.join(cur, p) if cur else p
                    pid = self._rel_to_iid.get(cur)
                    if pid and pid in selected:
                        should_check = True
                        break
            try:
                var.set(should_check)
            except Exception:
                pass
        cnt = sum(1 for vv,_,_,_ in self.checkbox_vars if vv.get())
        self.checked_count_var.set(cnt)

    def _on_right_click_menu(self, event):
        item_id = self.tree.identify_row(event.y)
        if item_id:
            self.tree.selection_set(item_id)
            context_menu = tk.Menu(self, tearoff=0)
            vals = self.tree.item(item_id, 'values')
            if vals and len(vals)>1 and vals[1] != 'folder':
                context_menu.add_command(label="View", command=lambda: self._view_file_content(item_id))
            context_menu.add_command(label="Open File/Folder", command=self._open_selected)
            context_menu.add_separator()
            context_menu.add_command(label="Copy to...", command=self._recover_selected)
            try: context_menu.tk_popup(event.x_root, event.y_root)
            finally: context_menu.grab_release()
        else:
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="Set Save Destination...", command=self._set_save_destination)
            try: menu.tk_popup(event.x_root, event.y_root)
            finally: menu.grab_release()

    def _on_recovery_label_right_click(self, event):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Save Recovered To...", command=self._save_recovered)
        menu.add_command(label="Set Save Destination...", command=self._set_save_destination)
        menu.add_separator()
        menu.add_command(label="Delete Recovered Files", command=self._delete_recovered)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _get_full_path(self, item_id):
        parts = [self.tree.item(item_id, 'text')]
        parent = self.tree.parent(item_id)
        while parent:
            parts.insert(0, self.tree.item(parent, 'text'))
            parent = self.tree.parent(parent)
        if parts[0] == "Present Data":
            rel = os.path.join(*parts[1:]) if len(parts)>1 else ""
            return os.path.join(self.recovery_root, "present_data", rel) if rel else os.path.join(self.recovery_root, "present_data")
        if parts[0] == "Recovered Data":
            rel = os.path.join(*parts[1:]) if len(parts)>1 else ""
            return os.path.join(self.restored_dir, rel) if rel else self.restored_dir
        return os.path.join(self.restored_dir, *parts)

    def _view_file_content(self, item_id):
        path = self._get_full_path(item_id)
        if not path or not os.path.exists(path): messagebox.showerror("Error","File not found"); return
        name = os.path.basename(path); ext = os.path.splitext(name)[1].lower()
        win = tk.Toplevel(self); win.title(f"Preview: {name}"); win.geometry("800x600")
        if ext in ['.jpg','.jpeg','.png','.gif','.bmp','.webp'] and HAVE_PIL:
            try:
                img = Image.open(path); img.thumbnail((780,580)); tk_img = ImageTk.PhotoImage(img)
                lbl = ttk.Label(win, image=tk_img); lbl.image = tk_img; lbl.pack(fill=tk.BOTH, expand=True)
            except Exception as e:
                ttk.Label(win, text=f"Could not preview image: {e}").pack(); self.log(f"Image preview failed for {path}: {e}", level=logging.WARNING)
        else:
            try:
                if os.path.getsize(path) < 200*1024 or ext in ['.txt','.log','.csv']:
                    text_area = tk.Text(win, wrap=tk.WORD, font=("Consolas",10)); text_area.pack(fill=tk.BOTH, expand=True)
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f: text_area.insert(tk.END, f.read(200*1024))
                    text_area.config(state=tk.DISABLED)
                else:
                    ttk.Label(win, text=f"No preview available for this file type/size ({ext})").pack(padx=20,pady=20)
            except Exception as e:
                ttk.Label(win, text=f"Preview failed: {e}").pack()

    def _open_selected(self):
        sel = self.tree.selection()
        if not sel: return
        full = self._get_full_path(sel[0])
        if os.path.exists(full):
            try:
                if os.path.isdir(full):
                    if platform.system()=='Linux': subprocess.Popen(['xdg-open', full])
                    else: os.startfile(full)
                else:
                    if platform.system()=='Linux': subprocess.Popen(['xdg-open', full])
                    else: os.startfile(full)
            except Exception as e: messagebox.showerror("Open failed", str(e))

    def _recover_selected(self):
        sel = self.tree.selection()
        if not sel: messagebox.showinfo("Select","Select files/folders to recover"); return
        dest = filedialog.askdirectory(title="Select destination folder");
        if not dest: return
        final = os.path.join(dest, os.path.basename(self.recovery_root)); os.makedirs(final, exist_ok=True)
        try:
            for item in sel:
                src = self._get_full_path(item);
                if os.path.isdir(src):
                    dst_rel = os.path.relpath(src, self.recovery_root) if src.startswith(self.recovery_root) else os.path.basename(src)
                    dst = os.path.join(final, dst_rel)
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                else:
                    dst_rel = os.path.relpath(src, self.restored_dir) if src.startswith(self.restored_dir) else os.path.relpath(src, self.recovery_root)
                    dst = os.path.join(final, dst_rel)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(src, dst)
            messagebox.showinfo("Recovered", f"Selected items copied to: {final}"); self.log("Selected items copied to user destination")
            try:
                self._populate_checkbox_list()
            except:
                pass
        except Exception as e: messagebox.showerror("Copy failed", str(e)); self.log(f"Recover selected failed: {e}", level=logging.ERROR)

    def _recover_checked(self):
        chosen = [(var, path, rel) for (var, path, rel, cb) in self.checkbox_vars if var.get()]
        if not chosen:
            messagebox.showinfo("No files","No checkboxes selected"); return
        dest = filedialog.askdirectory(title="Select destination folder for checked files")
        if not dest:
            return
        out_root = os.path.join(dest, os.path.basename(self.recovery_root))
        os.makedirs(out_root, exist_ok=True)
        errors = []
        for var, fp, rel in chosen:
            try:
                dst = os.path.join(out_root, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(fp, dst)
            except Exception as e:
                errors.append((rel, str(e)))
        if errors:
            msg = "Some files failed to copy:\n" + "\n".join([f"{r}: {e}" for r,e in errors])
            messagebox.showwarning("Partial failure", msg)
            self.log(f"Recover checked: partial failures: {errors}", level=logging.WARNING)
        else:
            messagebox.showinfo("Recovered", f"{len(chosen)} file(s) copied to {out_root}")
            self.log(f"Recovered {len(chosen)} checked file(s) to {out_root}")
        try:
            self._populate_checkbox_list()
        except:
            pass

    def _delete_recovered(self):
        if not self.recovery_root or not os.path.exists(self.recovery_root):
            messagebox.showinfo("No data","No recovered data"); return
        confirm = messagebox.askyesno("Delete","Delete recovered data? This cannot be undone.")
        if not confirm: return
        try:
            shutil.rmtree(self.recovery_root); self.tree.delete(*self.tree.get_children()); os.makedirs(self.recovery_root, exist_ok=True)
            self._clear_checkbox_list()
            messagebox.showinfo("Deleted","Recovered files deleted"); self.log("Recovered files deleted")
        except Exception as e: messagebox.showerror("Delete failed", str(e)); self.log(f"Delete failed: {e}", level=logging.ERROR)

    def _set_save_destination(self):
        try:
            dest = filedialog.askdirectory(title="Select default destination for recovered files")
            if not dest:
                return
            self.default_save_dest = dest
            self.log(f"Default save destination set: {dest}")
            messagebox.showinfo("Save Destination", f"Default save destination set to:\n{dest}")
        except Exception as e:
            self.log(f"_set_save_destination error: {e}", level=logging.ERROR); messagebox.showerror("Error", f"Failed to set save destination: {e}")

    # ---------------- reports ----------------
    def _refresh_reports_list(self):
        try:
            files = sorted([os.path.join(REPORTS_DIR,f) for f in os.listdir(REPORTS_DIR) if f.lower().endswith('.pdf')], key=os.path.getmtime, reverse=True)
            top5 = files[:5]
            display = [os.path.basename(f) for f in top5]
            self.reports_combo['values'] = display
            if display:
                self.reports_combo.current(0)
                self.reports_var.set(display[0])
                self.view_report_btn.config(state='normal')
                self.download_report_btn.config(state='normal')
            else:
                self.reports_combo.set('')
                self.view_report_btn.config(state='disabled')
                self.download_report_btn.config(state='disabled')
        except Exception as e:
            self.log(f"Failed to refresh reports list: {e}", level=logging.WARNING)

    def _get_selected_report_path(self):
        sel = self.reports_var.get()
        if not sel: return None
        candidate = os.path.join(REPORTS_DIR, sel)
        if os.path.exists(candidate):
            return candidate
        for f in os.listdir(REPORTS_DIR):
            if f.lower() == sel.lower():
                return os.path.join(REPORTS_DIR, f)
        return None

    def _open_selected_report(self):
        p = self._get_selected_report_path()
        if not p:
            messagebox.showinfo("No report","No report selected or file missing")
            return
        try:
            if platform.system()=='Linux': subprocess.Popen(['xdg-open', p])
            else: os.startfile(p)
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    def _download_selected_report(self):
        p = self._get_selected_report_path()
        if not p:
            messagebox.showinfo("No report","No report selected or file missing")
            return
        dst = filedialog.asksaveasfilename(title="Save report as...", defaultextension='.pdf', initialfile=os.path.basename(p), filetypes=[('PDF','*.pdf')])
        if not dst:
            return
        try:
            shutil.copy2(p, dst)
            messagebox.showinfo("Saved","Report saved to:\n" + dst)
            self.log(f"Report copied to {dst}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e)); self.log(f"Report save failed: {e}", level=logging.ERROR)

    def _show_report_view(self, pdf_path):
        try:
            win = tk.Toplevel(self); win.title("Report View"); win.geometry("700x160")
            lbl = ttk.Label(win, text=f"Latest report: {os.path.basename(pdf_path)}", font=("Helvetica",11,"bold"))
            lbl.pack(fill=tk.X, padx=12, pady=(12,6))
            path_lbl = ttk.Label(win, text=f"Path: {os.path.abspath(pdf_path)}", wraplength=660)
            path_lbl.pack(fill=tk.X, padx=12)
            btn_frame = ttk.Frame(win); btn_frame.pack(fill=tk.X, padx=12, pady=12)
            def _open():
                try:
                    if platform.system()=='Linux': subprocess.Popen(['xdg-open', pdf_path])
                    else: os.startfile(pdf_path)
                except Exception as e:
                    messagebox.showerror("Open failed", str(e))
            def _download():
                dst = filedialog.asksaveasfilename(title="Save report as...", defaultextension='.pdf', initialfile=os.path.basename(pdf_path), filetypes=[('PDF','*.pdf')])
                if not dst:
                    return
                try:
                    shutil.copy2(pdf_path, dst)
                    messagebox.showinfo("Saved","Report saved to:\n" + dst)
                except Exception as e:
                    messagebox.showerror("Save failed", str(e))
            ttk.Button(btn_frame, text="Open (External Viewer)", command=_open).pack(side=tk.LEFT, padx=6)
            ttk.Button(btn_frame, text="Download (Save As)", command=_download).pack(side=tk.LEFT, padx=6)
            ttk.Button(btn_frame, text="Close", command=win.destroy).pack(side=tk.RIGHT, padx=6)
        except Exception as e:
            self.log(f"Failed to open report view: {e}", level=logging.WARNING)

    # ---------------- post-processing & PDF generation ----------------
    def _post_process_and_report(self):
        try:
            self.log("Generating hashes & report")
            try:
                with open(self.hashes_path, 'w', encoding='utf-8') as hf:
                    hf.write("--- Recovered File Hashes ---\n")
                    for root, _, files in os.walk(self.recovery_root):
                        for fn in files:
                            if fn.lower().endswith('.dovecot'): continue
                            fp = os.path.join(root, fn)
                            if not os.access(fp, os.R_OK): continue
                            try:
                                md5 = hashlib.md5(); sha = hashlib.sha256()
                                with open(fp, 'rb') as fh:
                                    for chunk in iter(lambda: fh.read(8192), b''):
                                        md5.update(chunk); sha.update(chunk)
                                hf.write(f"File: {os.path.relpath(fp, self.recovery_root)}\n  MD5: {md5.hexdigest()}\n  SHA256: {sha.hexdigest()}\n\n")
                            except Exception as e:
                                self.file_logger.warning(str(e))
            except Exception as e:
                self.log(f"Failed to write hashes file: {e}", level=logging.WARNING)

            agg = {}; total_files = 0; total_size = 0
            for root, _, files in os.walk(self.recovery_root):
                for fn in files:
                    if fn.lower().endswith('.dovecot'): continue
                    fp = os.path.join(root, fn)
                    if not os.access(fp, os.R_OK): continue
                    try: sz = os.path.getsize(fp)
                    except: sz = 0
                    total_files += 1
                    total_size += sz
                    ext = os.path.splitext(fn)[1].lstrip('.').lower() or 'none'
                    if ext in self.OMIT_EXTENSIONS: continue
                    rec = agg.setdefault(ext, {'count':0, 'size':0})
                    rec['count'] += 1; rec['size'] += sz

            saved_location = os.path.abspath(self.recovery_root)
            duration = (self.end_time - self.start_time) if (self.start_time and self.end_time) else None

            device_parent = get_parent_device(self.selected_path) if self.selected_path else None
            parent_info = query_device_info(device_parent) if device_parent else {}
            cert = {
                'project_title': 'SafeDrive - Recovery Report',
                'selected_source': self.selected_label or os.path.basename(self.selected_image or ""),
                'parent_device': os.path.basename(parent_info.get('name','')) if parent_info else '',
                'parent_size': human_readable(int(parent_info.get('size')) if parent_info.get('size') and parent_info.get('size').isdigit() else (self.selected_size or 0)),
                'parent_type': parent_info.get('type',''),
                'parent_transport': parent_info.get('tran',''),
                'start_time': self.start_time.isoformat() if self.start_time else '',
                'end_time': self.end_time.isoformat() if self.end_time else '',
                'duration': str(duration) if duration else '',
                'data_recovered_in': saved_location,
                'files_recovered': total_files,
                'size_recovered_bytes': total_size,
                'size_recovered': human_readable(total_size),
                'saved_location': saved_location,
                'extension_table': agg,
                'hashes_file': os.path.abspath(self.hashes_path) if os.path.exists(self.hashes_path) else '',
                'log_file': os.path.abspath(self.logfile_path),
            }

            txtp = os.path.join(REPORTS_DIR, f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(txtp, 'w', encoding='utf-8') as rf:
                rf.write("=== SafeDrive Summary ===\n")
                rf.write(f"Date: {datetime.now().strftime('%Y-%m-%d')}\nTime: {datetime.now()}\n")
                rf.write(f"Source: {cert['selected_source']}\n")
                rf.write(f"Recovery Root: {cert['data_recovered_in']}\nStart: {cert['start_time']}\nEnd: {cert['end_time']}\nDuration: {cert['duration']}\n")
                rf.write(f"Size Recovered: {cert['files_recovered']}\nRecoverd Size: {cert['size_recovered']}\n\n--- By Extension ---\n")
                rf.write(f"{'Ext':15} {'Count':8} {'Size':12}\n")
                for ext, info in sorted(agg.items(), key=lambda x: (-x[1]['count'], x[0])):
                    rf.write(f"{ext:15} {info['count']:8} {human_readable(info['size']):12}\n")
            self.log(f"Summary text saved: {txtp}")

            if HAVE_REPORTLAB:
                self._write_pdf_report(cert)
                self._refresh_reports_list()
                # show report overview
                self.after(0, lambda: self._show_report_view(self.report_path))
            else:
                self._refresh_reports_list()

        except Exception as e:
            self.log(f"Post-process failed: {e}", level=logging.ERROR)

    def _write_pdf_report(self, cert):
        try:
            nowstr = datetime.now().strftime("%Y%m%d_%H%M%S")
            key = safe_file_name(cert.get('selected_source','recovery'))
            path = os.path.join(REPORTS_DIR, f"report_{key}_{nowstr}.pdf")
            self.report_path = path

            doc = SimpleDocTemplate(path, pagesize=A4,
                                    rightMargin=24, leftMargin=24,
                                    topMargin=24, bottomMargin=24)
            styles = getSampleStyleSheet()
            # header/title styles with eye-catching color
            title_style = ParagraphStyle(
                'title',
                parent=styles['Heading1'],
                fontName='Helvetica-Bold',
                fontSize=18,
                leading=22,
                alignment=1,   # center
                textColor=colors.white
            )
            subtitle_style = ParagraphStyle('subtitle', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=10, leading=12, textColor=colors.white, alignment=1)
            center_bold = ParagraphStyle('cb', parent=styles['Normal'], alignment=1, fontName='Helvetica-Bold', fontSize=10)
            normal_center = ParagraphStyle('nc', parent=styles['Normal'], alignment=1, fontSize=10)
            normal_just = ParagraphStyle('nj', parent=styles['Normal'], alignment=4, fontSize=9)   # justified
            normal = ParagraphStyle('n', parent=styles['Normal'], fontSize=10)

            elems = []

            # colored header block
            header_table = Table(
                [[Paragraph(cert.get('project_title','SafeDrive - Recovery Report'), title_style)]],
                colWidths=[doc.width]
            )
            header_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.Color(0.05,0.25,0.45)),
                ('ALIGN',(0,0),(-1,-1),'CENTER'),
                ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
                ('TOPPADDING',(0,0),(-1,-1),10),
                ('BOTTOMPADDING',(0,0),(-1,-1),10),
            ]))
            elems.append(header_table)
            elems.append(Spacer(1,8))

            # center metadata block (two-column but centered overall)
            meta_left = [
                ['Selected Source:', cert.get('selected_source') or 'Unknown'],
                ['Parent Device:', cert.get('parent_device') or 'Unknown'],
                ['Parent Size:', cert.get('parent_size') or 'Unknown'],
            ]
            meta_right = [
                ['Parent Type:', cert.get('parent_type') or 'Unknown'],
                ['Parent Transport:', cert.get('parent_transport') or 'Unknown'],
                ['Files Recovered:', str(cert.get('files_recovered') or 0)],
            ]
            # build a 2-column table so it looks centered
            meta_rows = []
            max_rows = max(len(meta_left), len(meta_right))
            for i in range(max_rows):
                l = meta_left[i] if i < len(meta_left) else ['', '']
                r = meta_right[i] if i < len(meta_right) else ['', '']
                meta_rows.append([l[0], l[1], r[0], r[1]])
            meta_table = Table(meta_rows, colWidths=[90, 150, 90, doc.width-90-150-90])
            meta_table.setStyle(TableStyle([
                ('FONTNAME',(0,0),(-1,-1),'Helvetica'),
                ('FONTSIZE',(0,0),(-1,-1),9),
                ('ALIGN',(0,0),(-1,-1),'LEFT'),
                ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
                ('INNERGRID',(0,0),(-1,-1),0.25,colors.whitesmoke),
                ('BOX',(0,0),(-1,-1),0.25,colors.whitesmoke),
                ('BACKGROUND',(0,0),(1,-1),colors.Color(0.96,0.97,0.98)),
                ('BACKGROUND',(2,0),(3,-1),colors.Color(0.98,0.98,0.99)),
            ]))
            elems.append(meta_table)
            elems.append(Spacer(1,10))

            # timing & location table centered
            time_rows = [
                ['Start Time', cert.get('start_time') or ''],
                ['End Time', cert.get('end_time') or ''],
                ['Duration', cert.get('duration') or ''],
                ['Recovered Location', cert.get('saved_location') or ''],
                ['Recoverd Size', cert.get('size_recovered') or '0B'],
            ]
            time_table = Table(time_rows, colWidths=[130, doc.width-130])
            time_table.setStyle(TableStyle([
                ('FONTNAME',(0,0),(-1,-1),'Helvetica'),
                ('FONTSIZE',(0,0),(-1,-1),9),
                ('VALIGN',(0,0),(-1,-1),'TOP'),
                ('BACKGROUND',(0,0),(-1,-1),colors.Color(0.97,0.98,1)),
                ('BOX',(0,0),(-1,-1),0.25,colors.grey),
            ]))
            elems.append(time_table)
            elems.append(Spacer(1,12))

            # Extension summary table with zebra rows and colors
            elems.append(Paragraph("<b>Extension Summary</b>", center_bold))
            ext_rows = [['Extension', 'Count', 'Total Size']]
            for ext, info in sorted(cert.get('extension_table', {}).items(), key=lambda x: (-x[1]['count'], x[0])):
                ext_rows.append([ext or '(none)', str(info['count']), human_readable(info['size'])])
            ext_table = Table(ext_rows, colWidths=[150, 80, doc.width-230])
            # zebra styling
            tbl_style = TableStyle([
                ('GRID',(0,0),(-1,-1),0.25,colors.grey),
                ('BACKGROUND',(0,0),(-1,0),colors.Color(0.9,0.95,1)),
                ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
                ('FONTSIZE',(0,0),(-1,-1),9),
                ('ALIGN',(1,1),(-1,-1),'RIGHT'),
            ])
            # zebra rows
            for i in range(1, len(ext_rows)):
                if i % 2 == 1:
                    tbl_style.add('BACKGROUND', (0,i), (-1,i), colors.Color(0.98,0.99,1))
                else:
                    tbl_style.add('BACKGROUND', (0,i), (-1,i), colors.white)
            ext_table.setStyle(tbl_style)
            elems.append(ext_table)
            elems.append(Spacer(1,12))

            # Hashes + log info
            elems.append(Paragraph(f"Hashes file generated: {os.path.basename(cert.get('hashes_file') or '')}", normal))
            elems.append(Paragraph(f"Hashes file path: {cert.get('hashes_file') or ''}", normal))
            elems.append(Paragraph(f"Log file: {cert.get('log_file') or ''}", normal))
            elems.append(Spacer(1,10))

            # disclaimer (justified)
            disclaimer = (
                "Disclaimer: This tool is provided 'as is' without any warranties, express or implied. "
                "The developer(s) make no guarantees regarding the accuracy, completeness, or effectiveness of the recovery process. "
                "Use of this tool is entirely at your own risk. The developer(s) shall not be held responsible for any data loss, corruption, hardware damage, "
                "or other issues that may arise from its use. This tool is intended for educational and recovery purposes only, and must not be used for any unlawful activity. "
                "Users are strongly advised to create backups before attempting recovery operations."
            )
            elems.append(Paragraph(disclaimer, normal_just))
            elems.append(Spacer(1,12))

            # footer
            footer_rows = [
                ['Generated automatically by SafeDrive', 'Date: ' + datetime.now().strftime('%Y-%m-%d') + '    Time: ' + datetime.now().strftime('%H:%M:%S')]
            ]
            footer_table = Table(footer_rows, colWidths=[doc.width*0.7, doc.width*0.3])
            footer_table.setStyle(TableStyle([
                ('FONTNAME',(0,0),(-1,-1),'Helvetica-Oblique'),
                ('FONTSIZE',(0,0),(-1,-1),8),
                ('ALIGN',(1,0),(1,0),'RIGHT'),
            ]))
            elems.append(footer_table)

            doc.build(elems)
            self.log(f"PDF report written: {path}")
            self.report_path = path
        except Exception as e:
            self.log(f"Failed to write PDF report: {e}", level=logging.ERROR)

    # ---------------- core scan runner ----------------
    def _run_photorec_scan(self, cmd, source, source_size):
        parsed_pct = 0.0; syntax_error = False; monitor_stop = threading.Event()

        # reliable size monitor: compute current bytes recovered (excluding omitted), compare to source_size
        def size_monitor():
            nonlocal parsed_pct
            last_count = 0; last_seen = time.time()
            while not (self.stop_event.is_set() or monitor_stop.is_set()):
                try:
                    recovered_size = 0; recovered_count = 0
                    if os.path.exists(self.recovery_root):
                        for root, _, files in os.walk(self.recovery_root):
                            for f in files:
                                if f.lower().endswith('.dovecot'):
                                    continue
                                fp = os.path.join(root, f)
                                try:
                                    if os.path.isfile(fp) and os.access(fp, os.R_OK):
                                        recovered_size += os.path.getsize(fp)
                                        recovered_count += 1
                                except: pass
                    # update shared counter
                    with self._lock_bytes:
                        self._bytes_recovered = recovered_size

                    denom = self._source_size if (self._source_size and self._source_size > 0) else None
                    pct_bytes = 0.0
                    if denom:
                        pct_bytes = (recovered_size / float(denom)) * 100.0
                        pct_bytes = min(99.0, pct_bytes)
                    # choose a heuristic combining any parsed_pct from photorec and bytes-based pct
                    use_pct = pct_bytes if denom else parsed_pct
                    use_pct = max(parsed_pct, use_pct)
                    # slight smoothing to avoid jumps
                    if recovered_count > last_count:
                        last_count = recovered_count; last_seen = time.time(); use_pct = min(99.0, use_pct + 0.6)
                    if time.time() - last_seen > 8:
                        use_pct = min(99.0, use_pct + 0.3)
                    # request animated progress update
                    self._set_progress_target_from_worker(use_pct)
                except: pass
                time.sleep(0.8)

        mon = threading.Thread(target=size_monitor, daemon=True); mon.start()

        def cb(line):
            nonlocal parsed_pct, syntax_error
            if not line: return
            clean = strip_ansi(line).strip()
            if not clean: return
            try:
                with open(self.logfile_path, 'a', encoding='utf-8') as lf: lf.write(f"{datetime.now().isoformat()} {clean}\n")
            except: pass
            self.file_logger.info(clean)
            self.gui_logger.info(re.sub(r'\bphotorec\b','[tool]', clean, flags=re.I))
            m = re.search(r'(\d{1,3})\s?%', clean)
            if m:
                try:
                    p = float(m.group(1)); p = min(99.0, p) if p < 100 else 99.0
                    parsed_pct = max(parsed_pct, p)
                    # animate to this parsed value
                    self._set_progress_target_from_worker(parsed_pct)
                except: pass
            m2 = re.search(r'Reading sector[^0-9]*([0-9,]+)\s*/\s*([0-9,]+)', clean, flags=re.I)
            if m2:
                try:
                    cur = int(m2.group(1).replace(',', '')); tot = int(m2.group(2).replace(',', ''))
                    p = min(99.0, (cur / max(1, tot)) * 100.0); parsed_pct = max(parsed_pct, p); self._set_progress_target_from_worker(parsed_pct)
                except: pass
            if 'syntax error' in clean.lower():
                syntax_error = True

        env = os.environ.copy(); env['TERM'] = 'dumb'
        rc = run_command_capture(cmd, update_cb=cb, stop_event=self.stop_event, proc_container=self.proc_container, env=env, logfile=self.logfile_path)
        monitor_stop.set()
        self.end_time = datetime.now()

        if syntax_error:
            self.log("PhotoRec syntax error detected. Check logs", level=logging.ERROR)
        else:
            if self.stop_event.is_set():
                self.log("Scan stopped by user", level=logging.WARNING)
            else:
                if rc == 127:
                    self.log("PhotoRec runtime missing", level=logging.ERROR)
                else:
                    self.log(f"PhotoRec finished with code {rc}")

        # final: compute a final progress value using bytes recovered or photorec pct
        final_pct = 100.0
        if rc != 0 or self.stop_event.is_set() or syntax_error:
            # if failure, show best-effort final percent
            with self._lock_bytes:
                br = self._bytes_recovered
            if self._source_size and self._source_size > 0:
                final_pct = min(100.0, (br / float(self._source_size)) * 100.0)
                final_pct = max(final_pct, float(self.progress['value'] or 0.0))
            else:
                final_pct = max(float(self.progress['value'] or 0.0), 99.0 if rc==0 else float(self.progress['value'] or 0.0))
        # animate to final
        self.after(0, lambda: self._animate_progress_to(final_pct))
        # reset mode indicator
        self.after(0, lambda: self._set_mode_indicator("IDLE"))
        self.after(0, lambda: self.status_var.set(""))
        self.after(0, lambda: self._set_progress_style_running(False))

        # wait for recovered files to appear/settle then organize & report
        files_found, appeared = self._wait_for_recovered_under_root(timeout=300, poll_interval=1.0)
        if not appeared:
            self.log(f"No recovered files detected in recovery root '{self.recovery_root}' after wait (count={files_found}). Proceeding anyway.", level=logging.WARNING)
        else:
            self.log(f"Recovered files detected: {files_found} under recovery root '{self.recovery_root}'", level=logging.INFO)

        try:
            self._organize_by_extension()
            self._populate_tree_with_present_and_recovered()
            self._populate_checkbox_list()
            self.log("Recovered-file organization & listing complete")
        except Exception as e:
            self.log(f"Post-scan populate failed: {e}", level=logging.ERROR)

        threading.Thread(target=self._post_process_and_report, daemon=True).start()
        with self.operation_lock:
            self.operation_thread = None
        self._set_idle_ui()

    def _wait_for_recovered_under_root(self, timeout=300, poll_interval=1.0):
        start = time.time(); seen = 0; root_dir = self.recovery_root or self.restored_dir or ""
        if not root_dir:
            return 0, False
        while time.time() - start < timeout:
            try:
                count = 0
                if os.path.exists(root_dir):
                    for _, _, files in os.walk(root_dir):
                        for f in files:
                            if f.lower().endswith('.dovecot'):
                                continue
                            count += 1
                if count != seen:
                    seen = count; self.file_logger.info(f"Detected recovered file count: {seen} under {root_dir}")
                if count > 0:
                    return count, True
            except: pass
            time.sleep(poll_interval)
        final = 0
        try:
            if os.path.exists(root_dir):
                for _, _, files in os.walk(root_dir):
                    for f in files:
                        if f.lower().endswith('.dovecot'): continue
                        final += 1
        except: pass
        return final, final > 0

    # ---------------- remaining UI helpers (unchanged) ----------------
    # (recover_selected, recover_checked, delete, save, open logs, etc. kept as before)
    # For brevity these methods were included earlier and remain the same in this file.

    def _save_recovered(self):
        if not self.recovery_root or not os.path.exists(self.recovery_root):
            messagebox.showinfo("No data","No recovered data to save"); return
        dest = filedialog.askdirectory(title="Select destination")
        if not dest: return
        out = os.path.join(dest, os.path.basename(self.recovery_root))
        try:
            shutil.copytree(self.recovery_root, out)
            messagebox.showinfo("Saved", f"Recovered data copied to {out}"); self.log(f"Recovered data copied to {out}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e)); self.log(f"Save failed: {e}", level=logging.ERROR)

    def _open_latest_report(self):
        try:
            files = sorted([os.path.join(REPORTS_DIR,f) for f in os.listdir(REPORTS_DIR)], key=os.path.getmtime, reverse=True)
            if not files: messagebox.showinfo("No reports","No reports found"); return
            p = files[0]
            if platform.system()=='Linux': subprocess.Popen(['xdg-open', p])
            else: os.startfile(p)
        except Exception as e: messagebox.showerror("Open failed", str(e))

    def _open_log_file(self):
        try:
            if os.path.exists(self.logfile_path):
                if platform.system()=='Linux': subprocess.Popen(['xdg-open', self.logfile_path])
                else: os.startfile(self.logfile_path)
            else: messagebox.showinfo("No log","No log file found")
        except Exception as e: messagebox.showerror("Open failed", str(e))

    def _clear_log_view(self):
        try:
            self.log_text.config(state=tk.NORMAL); self.log_text.delete("1.0", tk.END); self.log_text.config(state=tk.DISABLED)
            self.gui_logger.info("Log view cleared")
        except Exception as e:
            messagebox.showerror("Clear failed", str(e))

# ---------------- Entrypoint ----------------
def main():
    if os.name != 'nt' and os.geteuid() != 0:
        print("Run as root: sudo python3 safedrive_improved_progress_pdf_v2.py"); sys.exit(1)
    app = SafeDriveApp(); app.mainloop()

if __name__ == "__main__":
    main()
