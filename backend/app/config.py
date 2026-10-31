import os
from pathlib import Path
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

ROOT_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # CORS & Security
    ALLOWED_ORIGINS: Union[List[str], str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ]
    TRUSTED_HOSTS: Union[List[str], str] = ["127.0.0.1", "localhost"]

    # Storage
    DATABASE_URL: str = f"sqlite:///{ROOT_DIR / 'phantomshell.db'}"
    MAX_EVENT_RETENTION: int = 2000

    # Local AI (Ollama)
    OLLAMA_BASE_URL: str = "http://127.0.0.1:11434"
    OLLAMA_MODEL: str = "phi4-mini"
    OLLAMA_CONNECT_TIMEOUT: float = 3.0
    OLLAMA_REQUEST_TIMEOUT: float = 30.0
    OLLAMA_TEMPERATURE: float = 0.2
    OLLAMA_MAX_TOKENS: int = 512

    # Workspace Monitoring
    DEFAULT_MONITORED_DIR: str = str(ROOT_DIR / "demo" / "sandbox")

    # Detection Thresholds
    FILE_BURST_THRESHOLD: int = 10
    FILE_BURST_WINDOW_SECONDS: int = 5
    FAILED_OP_THRESHOLD: int = 3
    FAILED_OP_WINDOW_SECONDS: int = 15

    SUSPICIOUS_PROCESS_NAMES: Union[List[str], str] = [
        "mimikatz.exe", "nc.exe", "ncat.exe", "netcat.exe",
        "psexec.exe", "procdump.exe", "lazagne.exe", "bloodhound.exe",
        "cain.exe", "wireshark.exe", "evil.exe"
    ]

    SENSITIVE_PATHS: Union[List[str], str] = [
        ".ssh", ".aws", ".gnupg", ".env", "id_rsa", "id_ed25519",
        "credentials", "shadow", "passwd", "SAM", "SYSTEM"
    ]

    @field_validator("ALLOWED_ORIGINS", "TRUSTED_HOSTS", "SUSPICIOUS_PROCESS_NAMES", "SENSITIVE_PATHS", mode="before")
    @classmethod
    def parse_comma_separated(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore"
    }

settings = Settings()
