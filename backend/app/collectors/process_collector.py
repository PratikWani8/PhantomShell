import time
import uuid
import threading
import logging
from datetime import datetime
from typing import Set, Dict, Any, Optional
import psutil

from app.collectors.base import BaseCollector
from app.schemas.event import NormalizedEvent
from app.security.sanitization import InputSanitizer

logger = logging.getLogger("phantomshell.collector.process")

class ProcessCollector(BaseCollector):
    def __init__(self, check_interval: float = 2.5):
        super().__init__("process_collector")
        self.check_interval = check_interval
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._known_pids: Set[int] = set()
        self._seen_signatures: Set[str] = set()

    def _snapshot_pids(self) -> Set[int]:
        try:
            return set(psutil.pids())
        except Exception as e:
            self.last_error = f"Failed to snapshot PIDs: {str(e)}"
            return set()

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self.is_paused = False
        self._stop_event.clear()
        
        # Populate initial baseline snapshot so we don't alert on existing system processes
        self._known_pids = self._snapshot_pids()
        logger.info(f"Process collector baseline initialized with {len(self._known_pids)} processes.")
        
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        if not self.is_running:
            return
        self.is_running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None
        logger.info("Process collector stopped.")

    def _inspect_process(self, pid: int) -> Optional[Dict[str, Any]]:
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = "[ACCESS_DENIED_OR_UNAVAILABLE]"
            
            try:
                ppid = proc.ppid()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                ppid = None

            try:
                create_time = datetime.fromtimestamp(proc.create_time()).isoformat()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                create_time = datetime.utcnow().isoformat()

            return {
                "pid": pid,
                "name": InputSanitizer.sanitize_string(name),
                "exe": InputSanitizer.sanitize_string(exe),
                "ppid": ppid,
                "create_time": create_time
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as e:
            logger.debug(f"Process inspection exception for PID {pid}: {e}")
            return None

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                current_pids = self._snapshot_pids()
                new_pids = current_pids - self._known_pids

                for pid in new_pids:
                    if self._stop_event.is_set():
                        break
                    
                    info = self._inspect_process(pid)
                    if not info:
                        continue

                    # Deduplication signature based on process name and exe
                    sig = f"{info['name']}_{info.get('exe', '')}"
                    # Don't flood if same rapid short-lived tool respawns
                    is_frequent = sig in self._seen_signatures
                    self._seen_signatures.add(sig)

                    # Limit seen signatures cache
                    if len(self._seen_signatures) > 500:
                        self._seen_signatures.clear()

                    event = NormalizedEvent(
                        event_id=str(uuid.uuid4()),
                        timestamp=datetime.utcnow(),
                        event_type="process_spawn",
                        source=self.name,
                        severity="info",
                        pid=info["pid"],
                        process_name=info["name"],
                        parent_pid=info["ppid"],
                        executable_path=info["exe"],
                        evidence={
                            "pid": info["pid"],
                            "process_name": info["name"],
                            "parent_pid": info["ppid"],
                            "executable_path": info["exe"],
                            "create_time": info["create_time"],
                            "first_seen_instance": not is_frequent
                        },
                        collection_status="collected",
                        is_simulated=False
                    )
                    self.emit_event(event)

                self._known_pids = current_pids

            except Exception as e:
                self.last_error = f"Error in process monitor loop: {str(e)}"
                logger.error(self.last_error)

            self._stop_event.wait(self.check_interval)
