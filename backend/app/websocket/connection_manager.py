import json
import logging
from typing import Set, Dict, Any
from fastapi import WebSocket

logger = logging.getLogger("phantomshell.websocket")

class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Active connections: {len(self.active_connections)}")

    async def broadcast(self, message_type: str, data: Dict[str, Any]):
        """
        Broadcasts a typed message payload to all connected clients.
        message_type: 'event', 'incident', 'monitoring_status', 'ai_status', 'heartbeat'
        """
        if not self.active_connections:
            return

        payload = {
            "type": message_type,
            "data": data
        }
        json_data = json.dumps(payload, default=str)
        dead_connections = []

        for connection in list(self.active_connections):
            try:
                await connection.send_text(json_data)
            except Exception as e:
                logger.warning(f"Error sending message to websocket: {e}")
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)

ws_manager = ConnectionManager()
