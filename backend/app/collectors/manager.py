import logging
from typing import Dict, Optional, Callable
from app.collectors.base import BaseCollector
from app.collectors.process_collector import ProcessCollector
from app.collectors.file_collector import FileCollector
from app.collectors.command_collector import CommandCollector
from app.schemas.event import NormalizedEvent
from app.config import settings

logger = logging.getLogger("phantomshell.collectors.manager")

class CollectorManager:
    def __init__(self, monitored_directory: str = settings.DEFAULT_MONITORED_DIR):
        self.monitored_directory = monitored_directory
        self.is_monitoring_active = False
        self.is_paused = False
        self.event_dispatcher: Optional[Callable[[NormalizedEvent], None]] = None

        self.collectors: Dict[str, BaseCollector] = {
            "process_collector": ProcessCollector(check_interval=2.0),
            "file_collector": FileCollector(monitored_directory=self.monitored_directory),
            "command_collector": CommandCollector(monitored_directory=self.monitored_directory)
        }

        # Hook internal callbacks to our centralized handler
        for coll in self.collectors.values():
            coll.set_callback(self._on_collector_event)

    def set_dispatcher(self, dispatcher: Callable[[NormalizedEvent], None]):
        self.event_dispatcher = dispatcher

    def _on_collector_event(self, event: NormalizedEvent):
        if not self.is_monitoring_active and event.source != "command_collector":
            # Real OS background collectors only emit when monitoring is explicitly active
            return
        if self.is_paused:
            return
        if self.event_dispatcher:
            self.event_dispatcher(event)

    def start_monitoring(self):
        """Explicit user action to start active monitoring."""
        if self.is_monitoring_active:
            return
        self.is_monitoring_active = True
        self.is_paused = False
        logger.info("Explicit monitoring activated by user.")

        # Start enabled collectors
        for name, collector in self.collectors.items():
            if name == "command_collector":
                collector.start()
            # Default start real collectors when monitoring is enabled
            collector.start()

    def stop_monitoring(self):
        """Explicit user action to stop active monitoring."""
        self.is_monitoring_active = False
        for name, collector in self.collectors.items():
            if name != "command_collector": # Keep terminal collector alive for commands
                collector.stop()
        logger.info("Explicit monitoring stopped.")

    def pause_monitoring(self):
        self.is_paused = True
        for collector in self.collectors.values():
            collector.pause()
        logger.info("Monitoring paused.")

    def resume_monitoring(self):
        self.is_paused = False
        for collector in self.collectors.values():
            collector.resume()
        logger.info("Monitoring resumed.")

    def toggle_collector(self, name: str, enable: bool) -> bool:
        if name not in self.collectors:
            return False
        collector = self.collectors[name]
        if enable:
            if self.is_monitoring_active or name == "command_collector":
                collector.start()
        else:
            collector.stop()
        return True

    def update_monitored_directory(self, new_dir: str):
        self.monitored_directory = new_dir
        file_coll = self.collectors.get("file_collector")
        if isinstance(file_coll, FileCollector):
            file_coll.update_directory(new_dir)
        cmd_coll = self.collectors.get("command_collector")
        if isinstance(cmd_coll, CommandCollector):
            cmd_coll.update_directory(new_dir)
        logger.info(f"Updated monitored directory across collectors to: {new_dir}")

    def get_status(self) -> dict:
        return {
            "is_active": self.is_monitoring_active,
            "is_paused": self.is_paused,
            "monitored_directory": self.monitored_directory,
            "collectors": {name: coll.get_status() for name, coll in self.collectors.items()}
        }
