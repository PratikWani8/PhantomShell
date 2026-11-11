import abc
from datetime import datetime
from typing import Callable, Optional
from app.schemas.event import NormalizedEvent

class BaseCollector(abc.ABC):
    def __init__(self, name: str, event_callback: Optional[Callable[[NormalizedEvent], None]] = None):
        self.name = name
        self.event_callback = event_callback
        self.is_running = False
        self.is_paused = False
        self.events_collected = 0
        self.last_event_time: Optional[datetime] = None
        self.last_error: str = ""

    def set_callback(self, callback: Callable[[NormalizedEvent], None]):
        self.event_callback = callback

    def emit_event(self, event: NormalizedEvent):
        if self.is_paused:
            return
        self.events_collected += 1
        self.last_event_time = datetime.utcnow()
        if self.event_callback:
            self.event_callback(event)

    @abc.abstractmethod
    def start(self):
        pass

    @abc.abstractmethod
    def stop(self):
        pass

    def pause(self):
        self.is_paused = True

    def resume(self):
        self.is_paused = False

    def get_status(self) -> dict:
        return {
            "name": self.name,
            "running": self.is_running,
            "paused": self.is_paused,
            "events_collected": self.events_collected,
            "last_event_time": self.last_event_time.isoformat() if self.last_event_time else "never",
            "error_message": self.last_error
        }
