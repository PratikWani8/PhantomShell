from sqlalchemy import Column, String, Integer, Float, Boolean
from app.database.session import Base
from app.config import settings as default_cfg

class SettingsModel(Base):
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True, default=1)
    monitored_dir = Column(String(500), default=default_cfg.DEFAULT_MONITORED_DIR)

    # Collector toggles
    process_collector_enabled = Column(Boolean, default=False)
    file_collector_enabled = Column(Boolean, default=False)
    command_collector_enabled = Column(Boolean, default=True)

    # Thresholds
    file_burst_threshold = Column(Integer, default=default_cfg.FILE_BURST_THRESHOLD)
    file_burst_window_seconds = Column(Integer, default=default_cfg.FILE_BURST_WINDOW_SECONDS)
    failed_op_threshold = Column(Integer, default=default_cfg.FAILED_OP_THRESHOLD)
    failed_op_window_seconds = Column(Integer, default=default_cfg.FAILED_OP_WINDOW_SECONDS)

    # AI settings
    ai_model = Column(String(100), default=default_cfg.OLLAMA_MODEL)
    ai_timeout = Column(Float, default=default_cfg.OLLAMA_REQUEST_TIMEOUT)

    # UX preferences
    sound_enabled = Column(Boolean, default=True)
    crt_effects_enabled = Column(Boolean, default=True)
    reduced_motion = Column(Boolean, default=False)
