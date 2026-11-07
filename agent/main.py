'''Entry point for the Sentinel Cyber Security Suite Agent.
Launches the Tkinter GUI with a system tray icon and optional real-time monitor.
'''
import tkinter as tk
import threading
from gui import SentinelGUI
from scanner import ScanEngine
from vt_client import VirusTotalClient
from database import SentinelDatabase
from quarantine import QuarantineManager
from realtime_monitor import RealtimeMonitor
from tray_app import TrayApp


def main():
    root = tk.Tk()
    vt = VirusTotalClient()
    db = SentinelDatabase()
    quarantine = QuarantineManager()
    engine = ScanEngine(vt, db, quarantine)
    monitor = RealtimeMonitor(engine)
    gui = SentinelGUI(root, engine, vt, db, quarantine, monitor)

    # wire the log callback so monitor results appear in the GUI log
    def gui_log_callback(result):
        root.after(0, lambda r=result: gui._add_result_row(r))

    monitor.callback = gui_log_callback

    # start system tray in a background thread
    tray = TrayApp(gui, engine, monitor)
    tray_thread = threading.Thread(target=tray.run, daemon=True)
    tray_thread.start()

    root.protocol('WM_DELETE_WINDOW', lambda: gui._on_close(tray, monitor))
    root.mainloop()


if __name__ == '__main__':
    main()
