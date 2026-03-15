# Standard libraries
import json
import os
import signal
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path


class ScanStateManager:
    """
    Persist scan progress periodically and support safe resume for long-running scans.
    """

    VERSION = 1

    def __init__(
        self,
        state_file,
        enabled=True,
        persist_after_seconds=300,
        persist_interval_seconds=30,
        cleanup_on_success=False,
    ):
        self.state_file = Path(state_file)
        self.enabled = bool(enabled)
        self.persist_after_seconds = max(0, int(persist_after_seconds))
        self.persist_interval_seconds = max(5, int(persist_interval_seconds))
        self.cleanup_on_success = bool(cleanup_on_success)
        self.started_monotonic = time.time()
        self.last_persist_monotonic = 0.0
        self._original_sigint = None
        self._original_sigterm = None
        self._installed_signals = False
        self.data = {}

    @staticmethod
    def _now():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _safe_relpath(path_value):
        try:
            return str(path_value)
        except Exception:
            return ""

    def start_new(self, scan_fingerprint, scan_config):
        if not self.enabled:
            return
        self.data = {
            "version": self.VERSION,
            "scan_id": str(uuid.uuid4()),
            "status": "running",
            "created_at": self._now(),
            "updated_at": self._now(),
            "scan_fingerprint": scan_fingerprint,
            "scan_config": scan_config,
            "progress": {
                "current_stage": "initialization",
                "cursor": {},
                "heartbeat": {},
                "stages": {
                    "discovery": {"status": "pending"},
                    "pattern_matching": {
                        "status": "pending",
                        "completed_platforms": [],
                        "common_rules_done": False,
                    },
                    "path_analysis": {"status": "pending"},
                    "reporting": {"status": "pending"},
                },
                "counters": {},
            },
            "last_error": "",
        }
        self.persist(force=True)

    def load_for_resume(self, expected_fingerprint):
        if not self.enabled:
            return None
        if not self.state_file.exists():
            return None

        try:
            content = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return None

        if not isinstance(content, dict):
            return None
        if content.get("status") not in ("running", "failed", "interrupted"):
            return None
        if content.get("scan_fingerprint") != expected_fingerprint:
            return None

        self.data = content
        self.data["status"] = "running"
        self.data["updated_at"] = self._now()
        self.persist(force=True)
        return self.data

    def install_signal_handlers(self):
        if not self.enabled or self._installed_signals:
            return

        def _handler(signum, _frame):
            reason = "interrupted"
            if signum == signal.SIGTERM:
                reason = "terminated"
            self.mark_failed(reason)
            self.persist(force=True)
            raise SystemExit(130)

        self._original_sigint = signal.getsignal(signal.SIGINT)
        self._original_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)
        self._installed_signals = True

    def uninstall_signal_handlers(self):
        if not self._installed_signals:
            return
        if self._original_sigint is not None:
            signal.signal(signal.SIGINT, self._original_sigint)
        if self._original_sigterm is not None:
            signal.signal(signal.SIGTERM, self._original_sigterm)
        self._installed_signals = False

    def _stage_obj(self, stage_name):
        progress = self.data.setdefault("progress", {})
        stages = progress.setdefault("stages", {})
        return stages.setdefault(stage_name, {"status": "pending"})

    def update_stage(self, stage_name, status, details=None):
        if not self.enabled or not self.data:
            return
        self.data["progress"]["current_stage"] = stage_name
        stage = self._stage_obj(stage_name)
        stage["status"] = status
        if details and isinstance(details, dict):
            stage.update(details)
        self.data["updated_at"] = self._now()
        self.data.setdefault("progress", {})["heartbeat"] = {
            "timestamp": self._now(),
            "message": f"{stage_name}:{status}",
        }
        self.persist(force=True)

    def update_cursor(self, cursor_payload):
        if not self.enabled or not self.data or not isinstance(cursor_payload, dict):
            return
        progress = self.data.setdefault("progress", {})
        progress["cursor"] = cursor_payload
        self.data["updated_at"] = self._now()
        self.persist()

    def update_counters(self, counters):
        if not self.enabled or not self.data or not isinstance(counters, dict):
            return
        progress = self.data.setdefault("progress", {})
        curr = progress.setdefault("counters", {})
        curr.update(counters)
        self.data["updated_at"] = self._now()
        self.persist()

    def touch_heartbeat(self, message="", details=None):
        if not self.enabled or not self.data:
            return
        progress = self.data.setdefault("progress", {})
        payload = {
            "timestamp": self._now(),
            "message": str(message or "").strip(),
        }
        if isinstance(details, dict):
            payload.update(details)
        progress["heartbeat"] = payload
        self.data["updated_at"] = self._now()
        self.persist(force=True)

    def mark_platform_completed(self, platform_name):
        if not self.enabled or not self.data:
            return
        stage = self._stage_obj("pattern_matching")
        completed = stage.setdefault("completed_platforms", [])
        if platform_name not in completed:
            completed.append(platform_name)
        self.data["updated_at"] = self._now()
        self.persist()

    def mark_common_rules_completed(self):
        if not self.enabled or not self.data:
            return
        stage = self._stage_obj("pattern_matching")
        stage["common_rules_done"] = True
        self.data["updated_at"] = self._now()
        self.persist()

    def mark_path_analysis_completed(self):
        if not self.enabled or not self.data:
            return
        stage = self._stage_obj("path_analysis")
        stage["status"] = "completed"
        self.data["updated_at"] = self._now()
        self.persist()

    def mark_completed(self):
        if not self.enabled or not self.data:
            return
        self.data["status"] = "completed"
        self.data["updated_at"] = self._now()
        self.persist(force=True)
        if self.cleanup_on_success:
            try:
                self.state_file.unlink(missing_ok=True)
            except OSError:
                pass

    def mark_failed(self, error_message):
        if not self.enabled or not self.data:
            return
        err_text = str(error_message or "").strip()
        if err_text.lower() in {"interrupted", "terminated", "cancelled", "canceled"}:
            self.data["status"] = "interrupted"
        else:
            self.data["status"] = "failed" if err_text else "interrupted"
        self.data["last_error"] = err_text
        self.data["updated_at"] = self._now()

    def _should_persist(self, force=False):
        if force:
            return True
        elapsed = time.time() - self.started_monotonic
        if elapsed < self.persist_after_seconds:
            return False
        return (time.time() - self.last_persist_monotonic) >= self.persist_interval_seconds

    def persist(self, force=False):
        if not self.enabled or not self.data or not self._should_persist(force=force):
            return
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp_file = self.state_file.with_suffix(self.state_file.suffix + ".tmp")
        try:
            tmp_file.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
            os.replace(tmp_file, self.state_file)
            self.last_persist_monotonic = time.time()
        except OSError:
            # Keep scan running even if checkpoint write fails.
            pass

    def get_resume_progress(self):
        if not self.data:
            return {}
        return self.data.get("progress", {})
