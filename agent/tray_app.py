'''Sentinel System Tray Icon - quick access from tray.'''
import os
import tkinter as tk
from tkinter import filedialog, messagebox
import pystray
from PIL import Image, ImageDraw


def create_image(width=64, height=64):
    image = Image.new('RGB', (width, height), (0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.polygon([
        (width * 0.25, height * 0.15),
        (width * 0.75, height * 0.15),
        (width * 0.95, height * 0.45),
        (width * 0.75, height * 0.85),
        (width * 0.25, height * 0.85),
        (width * 0.05, height * 0.45),
    ], fill=(0, 120, 215))
    draw.line([
        (width * 0.35, height * 0.55),
        (width * 0.45, height * 0.70),
        (width * 0.65, height * 0.40),
    ], fill=(255, 255, 255), width=6)
    return image


class TrayApp:
    def __init__(self, gui, engine, monitor):
        self.gui = gui
        self.engine = engine
        self.monitor = monitor
        self._icon = None
        self._root = gui.root

    def run(self):
        image = create_image()
        menu = pystray.Menu(
            pystray.MenuItem('Open Sentinel', self._show_window),
            pystray.MenuItem('Scan Folder', self._scan_folder),
            pystray.MenuItem('Start Real-time Monitor', self._start_monitor),
            pystray.MenuItem('Stop Real-time Monitor', self._stop_monitor),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Exit Sentinel', self._exit_app),
        )
        self._icon = pystray.Icon('SentinelCyber', image,
                                  'Sentinel Cyber Security Suite', menu)
        self._icon.run()

    def _show_window(self, icon=None, item=None):
        self._root.after(0, self._root.deiconify)

    def _scan_folder(self, icon=None, item=None):
        folder = filedialog.askdirectory(parent=self._root)
        if folder:
            self._root.after(0, lambda: self.gui._scan_folder())

    def _start_monitor(self, icon=None, item=None):
        folder = filedialog.askdirectory(parent=self._root,
                                         title='Folder to monitor in real-time')
        if not folder:
            return
        self.monitor.add_watch(folder, recursive=True)
        if not self.monitor.is_running():
            self.monitor.start()
        self.gui.log('Real-time monitor started: ' + folder)

    def _stop_monitor(self, icon=None, item=None):
        self.monitor.stop()
        self.gui.log('Real-time monitor stopped.')

    def _exit_app(self, icon=None, item=None):
        self.monitor.stop()
        self._icon.stop()
        self._root.after(0, self._root.destroy)
