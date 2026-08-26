"""WebSocket Connection Manager for Real-time Dashboard Telemetry."""

import json
import logging
from typing import Any, Dict, List
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("onechance.websockets")


class ConnectionManager:
    """Manages active WebSocket connections to broadcast live telemetry & attack events."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new client connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"New WebSocket client connected. Active clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected client connection."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Active clients: {len(self.active_connections)}")

    async def broadcast_json(self, data: Dict[str, Any]) -> None:
        """Broadcast JSON payload to all connected dashboard clients."""
        if not self.active_connections:
            return

        payload = json.dumps(data)
        stale_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                stale_connections.append(connection)

        for stale in stale_connections:
            self.disconnect(stale)


manager = ConnectionManager()
