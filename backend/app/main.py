import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database.init_db import init_db
from app.api.routes import api_router
from app.api.demo_routes import demo_router
from app.websocket.connection_manager import ws_manager
from app.services.monitoring_service import monitoring_service

# Structured logging configuration
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("phantomshell")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize SQLite schema & default records
    logger.info("Initializing PhantomShell SQLite database...")
    init_db()

    # Wire asyncio event loop into monitoring service
    loop = asyncio.get_running_loop()
    monitoring_service.set_event_loop(loop)
    logger.info("PhantomShell backend initialized successfully on localhost.")
    
    yield

    # Shutdown: Stop any active OS collectors cleanly
    logger.info("Stopping PhantomShell background telemetry collectors...")
    await monitoring_service.stop()

app = FastAPI(
    title="PhantomShell Backend API",
    description="Deterministic security monitoring and eerie Ghost AI agent for local systems.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration restricted strictly to local origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Register REST routers
app.include_router(api_router)
app.include_router(demo_router)

# Root status
@app.get("/", tags=["System"])
async def root():
    return {
        "name": "PhantomShell",
        "description": "Ghost in the Machine - Local-First Haunted Terminal",
        "status": "online",
        "docs_url": "/docs"
    }

# =========================================================================
# WebSocket Endpoint: Real-time event and incident stream
# =========================================================================
@app.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    # Validate origin if provided
    origin = websocket.headers.get("origin")
    if origin and origin not in settings.ALLOWED_ORIGINS and not any(o in origin for o in ["localhost", "127.0.0.1"]):
        logger.warning(f"Rejected unauthorized WebSocket connection from origin: {origin}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws_manager.connect(websocket)
    try:
        # Send initial status handshake
        await websocket.send_json({
            "type": "handshake",
            "data": {
                "server": "PhantomShell",
                "monitoring": monitoring_service.get_status()
            }
        })
        while True:
            # Keep connection alive; accept optional ping/pong messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket exception: {e}")
        ws_manager.disconnect(websocket)
