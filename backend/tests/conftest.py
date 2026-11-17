import os
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure backend root is on Python path
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

TEST_DB_PATH = BACKEND_DIR / "test_phantom.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"
os.environ["LOG_LEVEL"] = "WARNING"
os.environ["OLLAMA_CONNECT_TIMEOUT"] = "0.5"
os.environ["YOLO_CONFIG_DIR"] = str(BACKEND_DIR / ".tmp")

from app.main import app
from app.database.session import Base, engine, SessionLocal
from app.database.init_db import init_db
from app.models.settings import SettingsModel
from app.models.event import EventModel
from app.models.incident import IncidentModel

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    if TEST_DB_PATH.exists():
        try:
            TEST_DB_PATH.unlink()
        except Exception:
            pass
    init_db()
    yield
    Base.metadata.drop_all(bind=engine)
    if TEST_DB_PATH.exists():
        try:
            TEST_DB_PATH.unlink()
        except Exception:
            pass

@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
