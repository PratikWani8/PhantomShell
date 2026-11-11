import os
import uuid
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from app.collectors.base import BaseCollector
from app.schemas.event import NormalizedEvent
from app.security.sanitization import InputSanitizer

logger = logging.getLogger("phantomshell.collector.file")

IGNORE_EXTENSIONS = {".tmp", ".swp", ".swo", ".pyc", ".log", ".lock"}
IGNORE_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".idea", ".vscode"}

class _WatchdogHandler(FileSystemEventHandler):
    def __init__(self, collector: "FileCollector"):
        super().__init__()
        self.collector = collector

    def _should_ignore(self, path_str: str) -> bool:
        try:
            p = Path(path_str)
            # Check directory parts
            for part in p.parts:
                if part in IGNORE_DIRS or part.startswith(".git"):
                    return True
            # Check extension
            if p.suffix.lower() in IGNORE_EXTENSIONS:
                return True
            # Check temporary swap files
            if p.name.startswith("~") or p.name.startswith(".#"):
                return True
            return False
        except Exception:
            return False

    def _handle_fs_event(self, event: FileSystemEvent, event_type: str, dest_path: Optional[str] = None):
        if self.collector.is_paused or not self.collector.is_running:
            return

        src = event.src_path
        if self._should_ignore(src):
            return

        try:
            base_dir = Path(self.collector.monitored_directory).resolve()
            src_path_obj = Path(src).resolve()
            try:
                rel_path = str(src_path_obj.relative_to(base_dir))
            except ValueError:
                rel_path = src_path_obj.name

            rel_dest_path = None
            if dest_path:
                try:
                    dest_obj = Path(dest_path).resolve()
                    rel_dest_path = str(dest_obj.relative_to(base_dir))
                except ValueError:
                    rel_dest_path = Path(dest_path).name

            # Sanitize path strings
            safe_rel_path = InputSanitizer.sanitize_string(rel_path.replace("\\", "/"))
            
            evidence = {
                "operation": event_type,
                "is_directory": event.is_directory,
                "relative_path": safe_rel_path,
                "monitored_workspace": str(base_dir),
                "timestamp": datetime.utcnow().isoformat()
            }
            if rel_dest_path:
                evidence["destination_relative_path"] = InputSanitizer.sanitize_string(rel_dest_path.replace("\\", "/"))

            norm_event = NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                event_type=f"file_{event_type}",
                source=self.collector.name,
                severity="info",
                relative_path=safe_rel_path,
                evidence=evidence,
                collection_status="collected",
                is_simulated=False
            )
            self.collector.emit_event(norm_event)
        except Exception as e:
            logger.error(f"Error processing watchdog event: {e}")

    def on_created(self, event):
        self._handle_fs_event(event, "create")

    def on_modified(self, event):
        self._handle_fs_event(event, "modify")

    def on_deleted(self, event):
        self._handle_fs_event(event, "delete")

    def on_moved(self, event):
        self._handle_fs_event(event, "move", getattr(event, 'dest_path', None))


class FileCollector(BaseCollector):
    def __init__(self, monitored_directory: str):
        super().__init__("file_collector")
        self.monitored_directory = monitored_directory
        self._observer: Optional[Observer] = None
        self._handler: Optional[_WatchdogHandler] = None

    def update_directory(self, new_dir: str):
        was_running = self.is_running
        if was_running:
            self.stop()
        self.monitored_directory = new_dir
        if was_running:
            self.start()

    def start(self):
        if self.is_running:
            return

        dir_path = Path(self.monitored_directory).resolve()
        # Security rule: Never monitor root or entire home directory
        user_home = Path.home().resolve()
        if dir_path == user_home or str(dir_path) in [str(user_home), "/", "C:\\", "c:\\"]:
            self.last_error = "Refused to monitor full root or home directory directly for security."
            logger.error(self.last_error)
            return

        if not dir_path.exists():
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self.last_error = f"Cannot create monitored directory: {str(e)}"
                logger.error(self.last_error)
                return

        try:
            self._observer = Observer()
            self._handler = _WatchdogHandler(self)
            self._observer.schedule(self._handler, str(dir_path), recursive=True)
            self._observer.start()
            self.is_running = True
            self.is_paused = False
            self.last_error = ""
            logger.info(f"FileCollector watching directory: {dir_path}")
        except Exception as e:
            self.last_error = f"Failed to start filesystem observer: {str(e)}"
            logger.error(self.last_error)
            self.is_running = False

    def stop(self):
        if not self.is_running:
            return
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=2.0)
            except Exception as e:
                logger.warning(f"Error stopping watchdog observer: {e}")
            self._observer = None
        self.is_running = False
        logger.info("FileCollector stopped.")
