import asyncio
import logging
from typing import Dict, Any, Optional

from app.collectors.manager import CollectorManager
from app.detection.engine import DetectionEngine
from app.services.event_service import event_service
from app.services.incident_service import incident_service
from app.ai.harness import AIHarness
from app.schemas.event import NormalizedEvent
from app.database.session import SessionLocal
from app.websocket.connection_manager import ws_manager
from app.models.settings import SettingsModel
from app.models.event import EventModel
from app.models.incident import IncidentModel

logger = logging.getLogger("phantomshell.services.monitoring")

class MonitoringService:
    def __init__(self):
        self.collector_manager = CollectorManager()
        self.detection_engine = DetectionEngine()
        self.ai_harness = AIHarness(detection_engine=self.detection_engine)
        self.loop: Optional[asyncio.AbstractEventLoop] = None

        # Wire collector manager callback
        self.collector_manager.set_dispatcher(self._handle_dispatched_event)

    def set_event_loop(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop

    def _handle_dispatched_event(self, event: NormalizedEvent):
        """Dispatches an event from any collector into storage, detection engine, and WS."""
        if not self.loop:
            try:
                self.loop = asyncio.get_running_loop()
            except RuntimeError:
                pass

        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self._process_event_async(event), self.loop)
        else:
            asyncio.run(self._process_event_async(event))

    async def _process_event_async(self, event: NormalizedEvent):
        db = SessionLocal()
        try:
            # 1. Record event
            await event_service.record_event(event, db)

            # 2. Retrieve detection thresholds from app settings
            settings_row = db.query(SettingsModel).filter(SettingsModel.id == 1).first()
            context = {}
            if settings_row:
                context = {
                    "file_burst_threshold": settings_row.file_burst_threshold,
                    "file_burst_window_seconds": settings_row.file_burst_window_seconds,
                    "failed_op_threshold": settings_row.failed_op_threshold,
                    "failed_op_window_seconds": settings_row.failed_op_window_seconds
                }

            # 3. Evaluate deterministic detection rules
            new_incidents = self.detection_engine.evaluate_event(event, context)

            # 4. Record new incidents
            for inc_data in new_incidents:
                logger.info(f"Triggered detection rule: {inc_data['rule_name']} (Risk: {inc_data['risk_score']})")
                await incident_service.create_incident(inc_data, db)

        except Exception as e:
            logger.error(f"Error processing event pipeline: {e}")
        finally:
            db.close()

    async def start(self):
        self.collector_manager.start_monitoring()
        await self._broadcast_status()

    async def stop(self):
        self.collector_manager.stop_monitoring()
        await self._broadcast_status()

    async def pause(self):
        self.collector_manager.pause_monitoring()
        await self._broadcast_status()

    async def resume(self):
        self.collector_manager.resume_monitoring()
        await self._broadcast_status()

    async def update_directory(self, new_dir: str):
        self.collector_manager.update_monitored_directory(new_dir)
        # Update settings in DB
        db = SessionLocal()
        try:
            row = db.query(SettingsModel).filter(SettingsModel.id == 1).first()
            if row:
                row.monitored_dir = new_dir
                db.commit()
        finally:
            db.close()
        await self._broadcast_status()

    async def toggle_collector(self, name: str, enabled: bool):
        self.collector_manager.toggle_collector(name, enabled)
        await self._broadcast_status()

    def get_status(self) -> Dict[str, Any]:
        mgr_status = self.collector_manager.get_status()
        db = SessionLocal()
        try:
            total_events = db.query(EventModel).count()
            active_incidents = db.query(IncidentModel).filter(IncidentModel.status == "open").count()
        finally:
            db.close()

        return {
            "is_active": mgr_status["is_active"],
            "is_paused": mgr_status["is_paused"],
            "monitored_directory": mgr_status["monitored_directory"],
            "collectors": mgr_status["collectors"],
            "total_events_captured": total_events,
            "active_incidents_count": active_incidents
        }

    async def _broadcast_status(self):
        status = self.get_status()
        await ws_manager.broadcast("monitoring_status", status)

monitoring_service = MonitoringService()
