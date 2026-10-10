"""Operation telemetry for long synchronous scan work (never skips analysis)."""
from contextlib import contextmanager
from threading import Event, Thread
import time


@contextmanager
def scan_operation(callback, *, interval=2.0, **payload):
    if not callable(callback):
        yield
        return
    stopped = Event()
    started = time.time()

    def emit():
        try:
            callback(dict(payload, operation_started_at=started, updated_at=time.time()))
        except Exception:
            # Telemetry must never change findings or interrupt analysis.
            pass

    def heartbeat():
        while not stopped.wait(interval):
            emit()

    emit()
    worker = Thread(target=heartbeat, name='scan-progress', daemon=True)
    worker.start()
    try:
        yield
    finally:
        stopped.set()
        worker.join()
