import json
import logging
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.event import EventModel
from app.schemas.event import NormalizedEvent, EventResponse, EventFilterParams
from app.websocket.connection_manager import ws_manager
from app.config import settings

logger = logging.getLogger("phantomshell.services.event")

class EventService:
    def __init__(self):
        pass

    async def record_event(self, event: NormalizedEvent, db: Session) -> EventModel:
        """Stores normalized event in database and broadcasts over WebSocket."""
        db_event = EventModel(
            id=event.event_id,
            timestamp=event.timestamp,
            event_type=event.event_type,
            source=event.source,
            severity=event.severity,
            pid=event.pid,
            process_name=event.process_name,
            parent_pid=event.parent_pid,
            executable_path=event.executable_path,
            relative_path=event.relative_path,
            evidence_json=json.dumps(event.evidence),
            collection_status=event.collection_status,
            is_simulated=event.is_simulated
        )
        db.add(db_event)
        db.commit()
        db.refresh(db_event)

        # Broadcast via WebSocket
        await ws_manager.broadcast("event", {
            "id": db_event.id,
            "timestamp": db_event.timestamp.isoformat(),
            "event_type": db_event.event_type,
            "source": db_event.source,
            "severity": db_event.severity,
            "pid": db_event.pid,
            "process_name": db_event.process_name,
            "parent_pid": db_event.parent_pid,
            "executable_path": db_event.executable_path,
            "relative_path": db_event.relative_path,
            "evidence": db_event.get_evidence(),
            "collection_status": db_event.collection_status,
            "is_simulated": db_event.is_simulated
        })

        # Check retention limits
        self._enforce_retention(db)

        return db_event

    def get_events(self, db: Session, params: EventFilterParams) -> Tuple[List[EventResponse], int]:
        query = db.query(EventModel)

        if params.event_type:
            query = query.filter(EventModel.event_type == params.event_type)
        if params.severity:
            query = query.filter(EventModel.severity == params.severity)
        if params.source:
            query = query.filter(EventModel.source == params.source)
        if params.is_simulated is not None:
            query = query.filter(EventModel.is_simulated == params.is_simulated)
        if params.search:
            search_term = f"%{params.search}%"
            query = query.filter(
                (EventModel.process_name.ilike(search_term)) |
                (EventModel.relative_path.ilike(search_term)) |
                (EventModel.evidence_json.ilike(search_term))
            )

        total = query.count()
        events = query.order_by(desc(EventModel.timestamp)).offset(params.offset).limit(params.limit).all()

        responses = [
            EventResponse(
                id=e.id,
                timestamp=e.timestamp,
                event_type=e.event_type,
                source=e.source,
                severity=e.severity,
                pid=e.pid,
                process_name=e.process_name,
                parent_pid=e.parent_pid,
                executable_path=e.executable_path,
                relative_path=e.relative_path,
                evidence=e.get_evidence(),
                collection_status=e.collection_status,
                is_simulated=e.is_simulated
            )
            for e in events
        ]
        return responses, total

    def get_event_by_id(self, db: Session, event_id: str) -> Optional[EventResponse]:
        e = db.query(EventModel).filter(EventModel.id == event_id).first()
        if not e:
            return None
        return EventResponse(
            id=e.id,
            timestamp=e.timestamp,
            event_type=e.event_type,
            source=e.source,
            severity=e.severity,
            pid=e.pid,
            process_name=e.process_name,
            parent_pid=e.parent_pid,
            executable_path=e.executable_path,
            relative_path=e.relative_path,
            evidence=e.get_evidence(),
            collection_status=e.collection_status,
            is_simulated=e.is_simulated
        )

    def _enforce_retention(self, db: Session):
        total = db.query(EventModel).count()
        if total > settings.MAX_EVENT_RETENTION:
            excess = total - settings.MAX_EVENT_RETENTION
            old_ids = [
                row[0] for row in db.query(EventModel.id)
                .order_by(EventModel.timestamp.asc())
                .limit(excess).all()
            ]
            if old_ids:
                db.query(EventModel).filter(EventModel.id.in_(old_ids)).delete(synchronize_session=False)
                db.commit()

    def clear_events(self, db: Session) -> int:
        count = db.query(EventModel).delete()
        db.commit()
        return count

event_service = EventService()
