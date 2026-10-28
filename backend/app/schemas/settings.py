from typing import Optional
from pydantic import BaseModel, Field

class SettingsResponse(BaseModel):
    monitored_dir: str
    process_collector_enabled: bool
    file_collector_enabled: bool
    command_collector_enabled: bool
    file_burst_threshold: int
    file_burst_window_seconds: int
    failed_op_threshold: int
    failed_op_window_seconds: int
    ai_model: str
    ai_timeout: float
    sound_enabled: bool
    crt_effects_enabled: bool
    reduced_motion: bool

    class Config:
        from_attributes = True

class SettingsUpdateRequest(BaseModel):
    monitored_dir: Optional[str] = None
    process_collector_enabled: Optional[bool] = None
    file_collector_enabled: Optional[bool] = None
    command_collector_enabled: Optional[bool] = None
    file_burst_threshold: Optional[int] = Field(None, ge=2, le=200)
    file_burst_window_seconds: Optional[int] = Field(None, ge=1, le=120)
    failed_op_threshold: Optional[int] = Field(None, ge=1, le=50)
    failed_op_window_seconds: Optional[int] = Field(None, ge=1, le=120)
    ai_model: Optional[str] = None
    ai_timeout: Optional[float] = Field(None, ge=1.0, le=120.0)
    sound_enabled: Optional[bool] = None
    crt_effects_enabled: Optional[bool] = None
    reduced_motion: Optional[bool] = None
