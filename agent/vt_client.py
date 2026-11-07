"""VirusTotal v3 API client with rate limiting."""
import time
import hashlib
import os
import requests
from config import (
    VT_API_KEY, VT_BASE_URL, VT_RATE_LIMIT_INTERVAL,
    MAX_FILE_SIZE_MB, MALICIOUS_THRESHOLD, HIGH_RISK_THRESHOLD,
    CRITICAL_THRESHOLD,
)


class VirusTotalError(Exception):
    pass


class VirusTotalClient:
    def __init__(self, api_key=VT_API_KEY):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": self.api_key})
        self._last_request_time = 0.0

    # ---- rate limiting ----
    def _wait_for_rate_limit(self):
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < VT_RATE_LIMIT_INTERVAL:
            time.sleep(VT_RATE_LIMIT_INTERVAL - elapsed)
        self._last_request_time = time.time()

    def _get(self, path, params=None):
        self._wait_for_rate_limit()
        resp = self.session.get(f"{VT_BASE_URL}{path}", params=params, timeout=30)
        return self._handle(resp)

    def _post(self, path, data=None, files=None):
        self._wait_for_rate_limit()
        resp = self.session.post(f"{VT_BASE_URL}{path}", data=data, files=files, timeout=60)
        return self._handle(resp)

    def _handle(self, resp):
        if resp.status_code == 429:
            raise VirusTotalError("VirusTotal rate limit exceeded.")
        if resp.status_code == 403:
            raise VirusTotalError("Invalid or missing VirusTotal API key.")
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise VirusTotalError("VirusTotal error " + str(resp.status_code) + ": " + resp.text)
        return resp.json()

    # ---- hashing ----
    @staticmethod
    def hash_file(path):
        h_sha256 = hashlib.sha256()
        h_md5 = hashlib.md5()
        h_sha1 = hashlib.sha1()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h_sha256.update(chunk)
                h_md5.update(chunk)
                h_sha1.update(chunk)
        return h_sha256.hexdigest(), h_md5.hexdigest(), h_sha1.hexdigest()

    # ---- look up by hash (no upload) ----
    def get_file_report(self, sha256):
        return self._get("/files/" + sha256)

    # ---- upload and scan ----
    def upload_file(self, path):
        with open(path, "rb") as f:
            files = {"file": (os.path.basename(path), f)}
            return self._post("/files", files=files)

    def get_analysis(self, analysis_id):
        return self._get("/analyses/" + analysis_id)

    # ---- high-level: scan a file intelligently ----
    def scan_file(self, path):
        sha256, md5, sha1 = self.hash_file(path)
        file_size = os.path.getsize(path)
        file_name = os.path.basename(path)

        result = {
            "hash": sha256, "md5": md5, "sha1": sha1,
            "file_path": path, "file_name": file_name, "file_size": file_size,
            "positives": 0, "total": 0, "malicious": 0, "suspicious": 0,
            "undetected": 0, "status": "unknown", "threat_level": "none",
            "scan_date": None, "source": "virustotal", "error": None,
        }

        # Step 1: check by hash (fast, no upload)
        report = self.get_file_report(sha256)
        if report:
            return self._normalize_report(report, path, file_name, file_size,
                                          sha256, md5, sha1, source="virustotal")

        # Step 2: upload if within size limit
        if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            result["error"] = "File too large (> " + str(MAX_FILE_SIZE_MB) + "MB) for free VT upload"
            result["status"] = "skipped"
            result["threat_level"] = "none"
            return result

        try:
            upload_resp = self.upload_file(path)
        except VirusTotalError as e:
            result["error"] = str(e)
            result["status"] = "error"
            return result

        analysis_id = upload_resp["data"]["id"]

        # Step 3: poll for completion
        for _ in range(30):
            analysis = self.get_analysis(analysis_id)
            if not analysis:
                break
            status = analysis["data"]["attributes"].get("status")
            if status == "completed":
                return self._normalize_analysis(analysis, path, file_name,
                                                file_size, sha256, md5, sha1)
            time.sleep(3)

        result["error"] = "Analysis timeout"
        result["status"] = "error"
        return result

    # ---- normalization ----
    def _normalize_report(self, report, path, file_name, file_size,
                          sha256, md5, sha1, source="virustotal"):
        attrs = report["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values())
        status, threat = self._classify(stats.get("malicious", 0), positives)
        return {
            "hash": sha256, "md5": md5, "sha1": sha1,
            "file_path": path, "file_name": file_name, "file_size": file_size,
            "positives": positives, "total": total,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "status": status, "threat_level": threat,
            "scan_date": attrs.get("last_analysis_date"),
            "source": source,
            "error": None,
            "results": attrs.get("last_analysis_results", {}),
            "type_description": attrs.get("type_description", ""),
            "meaningful_name": attrs.get("meaningful_name", ""),
        }

    def _normalize_analysis(self, analysis, path, file_name, file_size,
                            sha256, md5, sha1):
        attrs = analysis["data"]["attributes"]
        stats = attrs.get("stats", {})
        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values())
        status, threat = self._classify(stats.get("malicious", 0), positives)
        report = self.get_file_report(sha256)
        results = {}
        if report:
            results = report["data"]["attributes"].get("last_analysis_results", {})
        return {
            "hash": sha256, "md5": md5, "sha1": sha1,
            "file_path": path, "file_name": file_name, "file_size": file_size,
            "positives": positives, "total": total,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "status": status, "threat_level": threat,
            "scan_date": attrs.get("date"),
            "source": "virustotal",
            "error": None,
            "results": results,
        }

    @staticmethod
    def _classify(malicious, positives):
        if malicious >= CRITICAL_THRESHOLD or positives >= CRITICAL_THRESHOLD:
            return "malicious", "critical"
        if malicious >= HIGH_RISK_THRESHOLD or positives >= HIGH_RISK_THRESHOLD:
            return "malicious", "high"
        if malicious >= MALICIOUS_THRESHOLD or positives >= MALICIOUS_THRESHOLD:
            return "malicious", "medium"
        if positives > 0:
            return "suspicious", "low"
        return "clean", "none"
