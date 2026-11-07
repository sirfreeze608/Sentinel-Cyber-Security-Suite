'''Sentinel Intelligent Scanning Engine.
- Whitelist bypass
- Local hash cache (respects VT rate limits)
- High-risk file prioritization
- System directory skipping
- File size limits
- Management server sync
'''
import os
import threading
import hashlib
import requests
from datetime import datetime
from config import (
    HIGH_RISK_EXTENSIONS, SKIP_DIRECTORIES, HASH_CACHE_TTL_HOURS,
    MANAGEMENT_URL, AGENT_TOKEN, AGENT_ID,
)


class ScanEngine:
    def __init__(self, vt_client, db, quarantine):
        self.vt = vt_client
        self.db = db
        self.quarantine = quarantine
        self._stop = False
        self._lock = threading.Lock()
        self.auto_quarantine = False
        self.skip_system = True

    def stop(self):
        self._stop = True

    def resume(self):
        self._stop = False

    @staticmethod
    def _hash(path):
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    def _sync_to_management(self, result):
        """Push scan result to CS Department management server."""
        if not MANAGEMENT_URL or not AGENT_TOKEN or not AGENT_ID:
            return
        try:
            payload = {
                "agent_id": AGENT_ID,
                "file_path": result.get("file_path"),
                "file_name": result.get("file_name"),
                "file_hash": result.get("hash"),
                "status": result.get("status"),
                "threat_level": result.get("threat_level"),
                "positives": result.get("positives"),
                "total": result.get("total"),
                "malicious": result.get("malicious"),
                "suspicious": result.get("suspicious"),
                "undetected": result.get("undetected"),
                "action": result.get("action"),
                "scanned_at": result.get("scanned_at"),
            }
            headers = {"Authorization": "Bearer " + AGENT_TOKEN,
                       "Content-Type": "application/json"}
            requests.post(MANAGEMENT_URL + "/api/scan_result",
                          json=payload, headers=headers, timeout=5)
        except Exception:
            pass  # silent - management may be offline

    # ---- single file ----
    def scan_file(self, file_path, auto_quarantine=False):
        if self._stop:
            return None
        fhash = self._hash(file_path)
        if self.db.is_whitelisted(fhash):
            return {
                'file_path': file_path, 'status': 'whitelisted',
                'threat_level': 'none', 'skipped': True,
            }

        result = self.vt.scan_file(file_path)
        result['hash'] = fhash
        result['scanned_at'] = datetime.now().isoformat()
        result['action'] = 'none'
        result['agent_id'] = AGENT_ID

        # cache result
        self.db.save_result(result)

        # auto-quarantine if malicious
        if result['status'] == 'malicious' and auto_quarantine:
            try:
                q_path = self.quarantine.quarantine(
                    file_path, result['hash'], result['threat_level'])
                result['action'] = 'quarantined'
                result['quarantine_path'] = q_path
                self.db.add_quarantine({
                    'agent_id': AGENT_ID,
                    'original_path': file_path,
                    'quarantine_path': q_path,
                    'hash': result['hash'],
                    'reason': result['threat_level'],
                    'quarantined_at': datetime.now().isoformat(),
                })
            except Exception as e:
                result['action'] = 'quarantine_failed: ' + str(e)

        self.db.add_history(result)

        # push to management server
        self._sync_to_management(result)

        return result

    # ---- directory scan ----
    def scan_directory(self, directory, callback=None, auto_quarantine=False,
                       skip_system=True, max_files=None):
        '''Walk a directory and intelligently scan files.'''
        self._stop = False
        files = self._collect_files(directory, skip_system)
        # intelligent ordering: high-risk extensions first
        files.sort(key=lambda p: 0 if os.path.splitext(p)[1].lower()
                   in HIGH_RISK_EXTENSIONS else 1)

        scanned = 0
        threats = 0
        cleaned = 0
        skipped = 0
        results = []

        for file_path in files:
            if self._stop:
                break
            if max_files and scanned >= max_files:
                break
            if not os.path.isfile(file_path):
                continue

            # check cache first (intelligent: skip recently scanned)
            fhash = self._hash(file_path)
            cached = self.db.get_cached_result(fhash)
            if cached:
                cached['file_path'] = file_path
                cached['skipped'] = True
                cached['source'] = 'cache'
                if callback:
                    callback(cached)
                results.append(cached)
                skipped += 1
                if cached['status'] == 'malicious':
                    threats += 1
                continue

            result = self.scan_file(file_path, auto_quarantine=auto_quarantine)
            if result is None:
                break
            scanned += 1
            if result['status'] == 'malicious':
                threats += 1
                if result['action'] == 'quarantined':
                    cleaned += 1
            if callback:
                callback(result)
            results.append(result)

        return {
            'scanned': scanned,
            'threats': threats,
            'cleaned': cleaned,
            'skipped': skipped,
            'total': len(files),
            'results': results,
        }

    def _collect_files(self, directory, skip_system):
        files = []
        for root, dirs, filenames in os.walk(directory):
            dirs[:] = [d for d in dirs if not self._is_skip(
                os.path.join(root, d), skip_system)]
            for name in filenames:
                files.append(os.path.join(root, name))
        return files

    def _is_skip(self, path, skip_system):
        if not skip_system:
            return False
        norm = os.path.normpath(path).lower()
        for skip in SKIP_DIRECTORIES:
            if norm.startswith(skip.lower()):
                return True
        return False
