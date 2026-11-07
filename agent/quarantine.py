"""Sentinel Quarantine Manager - isolates infected files."""
import os
import shutil
from datetime import datetime
from config import QUARANTINE_DIR


class QuarantineManager:
    def __init__(self, quarantine_dir=QUARANTINE_DIR):
        self.quarantine_dir = quarantine_dir
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def quarantine(self, file_path, file_hash, reason="malicious"):
        if not os.path.exists(file_path):
            raise FileNotFoundError(file_path)
        file_name = os.path.basename(file_path)
        base, ext = os.path.splitext(file_name)
        q_path = os.path.join(self.quarantine_dir, file_name)
        counter = 1
        while os.path.exists(q_path):
            q_path = os.path.join(self.quarantine_dir, "{}_c{}{}".format(base, counter, ext))
            counter += 1
        shutil.move(file_path, q_path)
        return q_path

    def restore(self, quarantine_path, destination):
        shutil.move(quarantine_path, destination)

    def delete(self, quarantine_path):
        if os.path.exists(quarantine_path):
            os.remove(quarantine_path)

    def list_quarantined(self):
        files = []
        if not os.path.exists(self.quarantine_dir):
            return files
        for name in os.listdir(self.quarantine_dir):
            f = os.path.join(self.quarantine_dir, name)
            if os.path.isfile(f):
                files.append({
                    "name": name, "path": f,
                    "size": os.path.getsize(f),
                })
        return files
