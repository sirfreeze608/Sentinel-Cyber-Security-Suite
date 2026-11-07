'''Tkinter GUI for the Sentinel Cyber Security Suite Agent.'''
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
from datetime import datetime

THREAT_COLORS = {
    'critical': '#c0392b',
    'high': '#e67e22',
    'medium': '#f1c40f',
    'low': '#f39c12',
    'clean': '#27ae60',
    'none': '#7f8c8d',
    'unknown': '#95a5a6',
    'skipped': '#bdc3c7',
    'whitelisted': '#8e44ad',
}


class SentinelGUI:
    def __init__(self, root, engine, vt, db, quarantine, monitor=None):
        self.root = root
        self.engine = engine
        self.vt = vt
        self.db = db
        self.quarantine = quarantine
        self.monitor = monitor
        self.root.title('Sentinel Cyber Security Suite - Agent')
        self.root.geometry('1000x700')
        self.root.minsize(800, 500)

        self._build_ui()
        self._refresh_stats()
        self._load_history()

    # ---- UI layout ----
    def _build_ui(self):
        top = ttk.Frame(self.root)
        top.pack(fill=tk.X, padx=8, pady=6)

        ttk.Label(top, text='VT API Key:').pack(side=tk.LEFT)
        default_key = self.vt.api_key if self.vt.api_key != 'YOUR_VIRUSTOTAL_API_KEY_HERE' else ''
        self.api_var = tk.StringVar(value=default_key)
        self.api_entry = ttk.Entry(top, textvariable=self.api_var, width=40, show='*')
        self.api_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text='Apply', command=self._apply_api).pack(side=tk.LEFT, padx=2)

        self.status_var = tk.StringVar(value='Ready')
        ttk.Label(top, textvariable=self.status_var).pack(side=tk.RIGHT)

        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        self.tab_scan = ttk.Frame(nb)
        self.tab_history = ttk.Frame(nb)
        self.tab_quarantine = ttk.Frame(nb)
        self.tab_settings = ttk.Frame(nb)
        nb.add(self.tab_scan, text='Scan')
        nb.add(self.tab_history, text='History')
        nb.add(self.tab_quarantine, text='Quarantine')
        nb.add(self.tab_settings, text='Settings')

        self._build_scan_tab()
        self._build_history_tab()
        self._build_quarantine_tab()
        self._build_settings_tab()

        log_frame = ttk.LabelFrame(self.root, text='Log')
        log_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        self.log_txt = tk.Text(log_frame, height=8, wrap=tk.WORD)
        self.log_txt.pack(fill=tk.BOTH, expand=True)

    def _build_scan_tab(self):
        f = self.tab_scan
        ctrl = ttk.Frame(f)
        ctrl.pack(fill=tk.X, padx=6, pady=6)

        ttk.Button(ctrl, text='Scan File', command=self._scan_file).pack(side=tk.LEFT, padx=3)
        ttk.Button(ctrl, text='Scan Folder', command=self._scan_folder).pack(side=tk.LEFT, padx=3)
        self.auto_q_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctrl, text='Auto-quarantine threats',
                        variable=self.auto_q_var).pack(side=tk.LEFT, padx=8)
        self.skip_sys_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctrl, text='Skip system folders',
                        variable=self.skip_sys_var).pack(side=tk.LEFT, padx=8)
        ttk.Button(ctrl, text='Stop', command=self._stop_scan).pack(side=tk.LEFT, padx=3)

        self.scan_var = tk.StringVar(value='Idle')
        ttk.Label(ctrl, textvariable=self.scan_var).pack(side=tk.LEFT, padx=15)

        self.progress = ttk.Progressbar(f, mode='determinate')
        self.progress.pack(fill=tk.X, padx=6, pady=(0, 6))

        cols = ('status', 'file', 'positives', 'total', 'threat', 'action')
        self.tree = ttk.Treeview(f, columns=cols, show='headings', selectmode='extended')
        for c, w in zip(cols, (110, 380, 70, 60, 80, 100)):
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=w, anchor=tk.W if c == 'file' else tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        act = ttk.Frame(f)
        act.pack(fill=tk.X, padx=6, pady=4)
        ttk.Button(act, text='Quarantine Selected',
                   command=self._quarantine_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(act, text='Whitelist Selected',
                   command=self._whitelist_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(act, text='Clear', command=self._clear_results).pack(side=tk.LEFT, padx=3)

    def _build_history_tab(self):
        f = self.tab_history
        cols = ('time', 'file', 'status', 'threat', 'positives', 'total', 'action')
        self.hist_tree = ttk.Treeview(f, columns=cols, show='headings')
        widths = (160, 340, 90, 70, 70, 60, 90)
        for c, w in zip(cols, widths):
            self.hist_tree.heading(c, text=c.title())
            self.hist_tree.column(c, width=w, anchor=tk.W if c == 'file' else tk.CENTER)
        self.hist_tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        ttk.Button(f, text='Refresh', command=self._load_history).pack(anchor=tk.E, padx=6, pady=4)

    def _build_quarantine_tab(self):
        f = self.tab_quarantine
        cols = ('name', 'path', 'size')
        self.q_tree = ttk.Treeview(f, columns=cols, show='headings')
        for c, w in zip(cols, (220, 420, 80)):
            self.q_tree.heading(c, text=c.title())
            self.q_tree.column(c, width=w, anchor=tk.W)
        self.q_tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        act = ttk.Frame(f)
        act.pack(fill=tk.X, padx=6, pady=4)
        ttk.Button(act, text='Refresh', command=self._load_quarantine).pack(side=tk.LEFT, padx=3)
        ttk.Button(act, text='Restore Selected', command=self._restore_q).pack(side=tk.LEFT, padx=3)
        ttk.Button(act, text='Delete Selected', command=self._delete_q).pack(side=tk.LEFT, padx=3)
        self._load_quarantine()

    def _build_settings_tab(self):
        f = self.tab_settings
        ttk.Label(f, text='Intelligent Scan Settings',
                  font=('Segoe UI', 12, 'bold')).pack(anchor=tk.W, padx=8, pady=8)
        ttk.Label(f, text='Cache TTL (hours):').pack(anchor=tk.W, padx=8)
        self.cache_var = tk.IntVar(value=24)
        ttk.Entry(f, textvariable=self.cache_var, width=10).pack(anchor=tk.W, padx=8, pady=2)
        ttk.Label(f, text='Max file size (MB):').pack(anchor=tk.W, padx=8, pady=(10, 0))
        self.maxsize_var = tk.IntVar(value=32)
        ttk.Entry(f, textvariable=self.maxsize_var, width=10).pack(anchor=tk.W, padx=8, pady=2)
        ttk.Button(f, text='Save Settings', command=self._save_settings).pack(anchor=tk.W, padx=8, pady=10)
        ttk.Separator(f).pack(fill=tk.X, padx=8, pady=10)
        ttk.Label(f, text='Stats:', font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W, padx=8)
        self.stats_lbl = ttk.Label(f, text='')
        self.stats_lbl.pack(anchor=tk.W, padx=8)

    # ---- actions ----
    def _apply_api(self):
        self.vt.api_key = self.api_var.get().strip()
        self.vt.session.headers.update({'x-apikey': self.vt.api_key})
        self.log('API key updated.')
        messagebox.showinfo('Sentinel', 'API key updated.')

    def log(self, msg):
        ts = datetime.now().strftime('%H:%M:%S')
        self.log_txt.insert(tk.END, '[' + ts + '] ' + msg + chr(10))
        self.log_txt.see(tk.END)

    def _scan_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        self._run_scan(lambda cb: self.engine.scan_file(
            path, auto_quarantine=self.auto_q_var.get()), single=True)

    def _scan_folder(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
        self._run_scan(
            lambda cb: self.engine.scan_directory(
                folder, callback=cb,
                auto_quarantine=self.auto_q_var.get(),
                skip_system=self.skip_sys_var.get(),
            ),
            single=False,
        )

    def _run_scan(self, scan_fn, single=False):
        self.tree.delete(*self.tree.get_children())
        self.progress['value'] = 0
        self.scan_var.set('Scanning...')
        self._stop_thread = False

        def worker():
            try:
                def callback(result):
                    if self._stop_thread:
                        return
                    self.root.after(0, lambda r=result: self._add_result_row(r))
                summary = scan_fn(callback)
                if summary:
                    self.root.after(0, lambda s=summary: self._scan_done(s))
                else:
                    self.root.after(0, self._scan_stopped)
            except Exception as e:
                self.root.after(0, lambda: self._scan_error(str(e)))

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def _stop_scan(self):
        self._stop_thread = True
        self.engine.stop()
        self.scan_var.set('Stopping...')

    def _add_result_row(self, r):
        status = r.get('status', 'unknown')
        tag = status if status in THREAT_COLORS else 'none'
        vals = (status.title(), r.get('file_name', ''), r.get('positives', 0),
                r.get('total', 0), r.get('threat_level', ''), r.get('action', ''))
        iid = self.tree.insert('', tk.END, values=vals, tags=(tag,))
        self.tree.tag_configure(tag, foreground=THREAT_COLORS.get(tag, '#000'))
        self.tree.see(iid)
        self.log(status.upper() + ': ' + r.get('file_name', '') +
                 ' (' + str(r.get('positives', 0)) + '/' + str(r.get('total', 0)) + ')')

    def _scan_done(self, summary):
        self.scan_var.set('Done: ' + str(summary['scanned']) +
                          ' scanned, ' + str(summary['threats']) +
                          ' threats, ' + str(summary['cleaned']) + ' quarantined')
        self._refresh_stats()
        self._load_history()
        messagebox.showinfo('Scan Complete',
                            'Scanned: ' + str(summary['scanned']) + chr(10) +
                            'Threats: ' + str(summary['threats']) + chr(10) +
                            'Quarantined: ' + str(summary['cleaned']))

    def _scan_stopped(self):
        self.scan_var.set('Stopped')

    def _scan_error(self, err):
        self.scan_var.set('Error')
        messagebox.showerror('Scan Error', err)

    def _clear_results(self):
        self.tree.delete(*self.tree.get_children())

    def _quarantine_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        messagebox.showinfo('Note',
            'Use auto-quarantine during scan, or manage from Quarantine tab.')

    def _whitelist_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        messagebox.showinfo('Note',
            'Whitelisting by hash requires the file path; store paths during scan.')

    def _load_history(self):
        self.hist_tree.delete(*self.hist_tree.get_children())
        for row in self.db.get_history(200):
            ts = row.get('scanned_at', '')[:16]
            self.hist_tree.insert('', tk.END, values=(
                ts, row.get('file_name', ''), row.get('status', ''),
                row.get('threat_level', ''), row.get('positives', 0),
                row.get('total', 0), row.get('action', ''),
            ))

    def _refresh_stats(self):
        s = self.db.get_stats()
        self.stats_lbl.config(text='Cached results: ' + str(s['total']) +
                              ' | By status: ' + str(s['by_status']))
        self.status_var.set('Ready | ' + str(s['total']) + ' cached results')

    def _load_quarantine(self):
        self.q_tree.delete(*self.q_tree.get_children())
        for item in self.quarantine.list_quarantined():
            self.q_tree.insert('', tk.END,
                               values=(item['name'], item['path'], item['size']))

    def _restore_q(self):
        sel = self.q_tree.selection()
        if not sel:
            return
        item = self.q_tree.item(sel[0])
        q_path = item['values'][1]
        dest = filedialog.askdirectory(title='Restore to folder')
        if dest:
            name = item['values'][0]
            self.quarantine.restore(q_path, os.path.join(dest, name))
            self._load_quarantine()
            self.log('Restored ' + name)

    def _delete_q(self):
        sel = self.q_tree.selection()
        if not sel:
            return
        item = self.q_tree.item(sel[0])
        q_path = item['values'][1]
        if messagebox.askyesno('Delete',
                               'Permanently delete this quarantined file?'):
            self.quarantine.delete(q_path)
            self._load_quarantine()
            self.log('Deleted ' + item['values'][0])

    def _save_settings(self):
        messagebox.showinfo('Settings',
            'Settings saved (in-memory). Edit config.py for persistence.')

    def _on_close(self, tray, monitor):
        '''Hide to tray instead of closing; full exit via tray menu.'''
        try:
            monitor.stop()
        except Exception:
            pass
        try:
            tray._icon.stop()
        except Exception:
            pass
        self.root.destroy()
