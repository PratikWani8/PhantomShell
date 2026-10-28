from app.database.session import engine, Base, SessionLocal
from app.models.event import EventModel
from app.models.incident import IncidentModel
from app.models.settings import SettingsModel

def init_db():
    """Initializes tables and seeds default settings if needed."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing = db.query(SettingsModel).filter(SettingsModel.id == 1).first()
        if not existing:
            default_settings = SettingsModel(id=1)
            db.add(default_settings)
            db.commit()
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
