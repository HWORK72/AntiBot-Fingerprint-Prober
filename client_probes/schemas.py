from pydantic import BaseModel, Field


class WebGLReport(BaseModel):
    vendor: str = Field(default="")
    renderer: str = Field(default="")
    unmasked_vendor: str = Field(default="")
    unmasked_renderer: str = Field(default="")
    gl_version: str = Field(default="")
    shading_language_version: str = Field(default="")
    extensions_count: int = Field(default=0)


class AudioContextReport(BaseModel):
    sample_rate: float = Field(default=0.0)
    state: str = Field(default="")
    max_channel_count: int = Field(default=0)
    oscillator_hash: str = Field(default="")


class CanvasReport(BaseModel):
    geometry_hash: str = Field(default="")
    text_hash: str = Field(default="")
    is_canvas_tainted: bool = Field(default=False)
    noise_detected: bool = Field(default=False)


class WorkerConsistencyReport(BaseModel):
    worker_supported: bool = Field(default=True)
    user_agent_match: bool = Field(default=True)
    hardware_concurrency_match: bool = Field(default=True)
    languages_match: bool = Field(default=True)
    worker_user_agent: str = Field(default="")
    worker_concurrency: int = Field(default=0)
    worker_languages: list[str] = Field(default_factory=list)


class CDPReport(BaseModel):
    runtime_enable_leaks: bool = Field(default=False)
    cdc_markers_found: list[str] = Field(default_factory=list)
    stack_trace_anomaly: bool = Field(default=False)
    native_fn_tampered: bool = Field(default=False)


class ClientProbePayload(BaseModel):
    user_agent: str
    webdriver_flag: bool = Field(default=False)
    plugins_length: int = Field(default=0)
    languages: list[str] = Field(default_factory=list)
    hardware_concurrency: int = Field(default=0)
    device_memory: float | None = Field(default=None)
    webgl: WebGLReport
    audio: AudioContextReport
    canvas: CanvasReport
    worker_check: WorkerConsistencyReport
    cdp_check: CDPReport