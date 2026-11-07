'''Sentinel Real-time Folder Monitoring (watchdog).
Watches folders and auto-scans new/modified files.
'''
import os
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class ScanEventHandler(FileSystemEventHandler):
    def __init__(self, engine, callback=None, cooldown_seconds=2.0):
        super().__init__()
        self.engine = engine
        self.callback = callback
        self.cooldown_seconds = cooldown_seconds
        self._last_scan = {}
        self._lock = threading.Lock()

    def _should_scan(self, path):
        now = time.time()
        with self._lock:
            last = self._last_scan.get(path, 0)
            if now - last < self.cooldown_seconds:
                return False
            self._last_scan[path] = now
            return True

    def _scan_if_needed(self, path):
        if not os.path.isfile(path):
            return
        if not self._should_scan(path):
            return
        try:
            result = self.engine.scan_file(path, auto_quarantine=True)
            if result and self.callback:
                self.callback(result)
        except Exception as e:
            if self.callback:
                self.callback({'status': 'error',
                               'file_name': os.path.basename(path),
                               'error': str(e), 'threat_level': 'none'})

    def on_created(self, event):
        if not event.is_directory:
            self._scan_if_needed(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._scan_if_needed(event.src_path)


class RealtimeMonitor:
    def __init__(self, engine, callback=None):
        self.engine = engine
        self.callback = callback
        self.observer = Observer()
        self._handler = None
        self._watch_paths = []
        self._thread = None
        self._stop = False

    def add_watch(self, path, recursive=True):
        if os.path.isdir(path) and path not in self._watch_paths:
            self._watch_paths.append(path)
            if self._handler:
                self.observer.schedule(self._handler, path, recursive=recursive)

    def remove_watch(self, path):
        if path in self._watch_paths:
            self._watch_paths.remove(path)

    def start(self):
        if self._handler is None:
            self._handler = ScanEventHandler(
                self.engine, callback=self.callback)
            for p in self._watch_paths:
                self.observer.schedule(self._handler, p, recursive=True)
        self._stop = False
        self.observer.start()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop:
            time.sleep(1)

    def stop(self):
        self._stop = True
        try:
            self.observer.stop()
            self.observer.join()
        except Exception:
            pass

    def is_running(self):
        return self.observer.is_alive()
