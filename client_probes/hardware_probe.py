from pydantic import BaseModel, Field
from client_probes.schemas import WebGLReport, AudioContextReport, CanvasReport

SUSPICIOUS_RENDERERS: tuple[str, ...] = (
    "swiftshader",
    "llvmpipe",
    "softpipe",
    "microsoft basic render driver",
    "mesa off-screen",
    "google cloud",
    "vmware",
    "virtualbox"
)


class HardwareVerdict(BaseModel):
    is_virtual_hardware: bool = Field(default=False)
    is_canvas_manipulated: bool = Field(default=False)
    anomalies: list[str] = Field(default_factory=list)


class HardwareAnalyzer:

    @classmethod
    def inspect(cls, webgl: WebGLReport, audio: AudioContextReport, canvas: CanvasReport) -> HardwareVerdict:
        anomalies: list[str] = []
        is_vm: bool = False

        renderer_lower: str = webgl.unmasked_renderer.lower()
        vendor_lower: str = webgl.unmasked_vendor.lower()

        for needle in SUSPICIOUS_RENDERERS:
            if needle in renderer_lower or needle in vendor_lower:
                is_vm = True
                anomalies.append(f"Программная эмуляция GPU в WebGL: '{webgl.unmasked_renderer}' (признак Headless браузера на сервере)")
                break

        if webgl.extensions_count < 10 and webgl.unmasked_renderer != "":
            anomalies.append(f"Подозрительно малое количество WebGL-расширений ({webgl.extensions_count})")

        if canvas.noise_detected:
            anomalies.append("Обнаружен искусственный шум в Canvas (Canvas Fingerprint Poisoning)")

        if audio.sample_rate not in (44100.0, 48000.0, 96000.0) and audio.sample_rate != 0.0:
            anomalies.append(f"Аномальная частота AudioContext ({audio.sample_rate} Hz)")

        return HardwareVerdict(
            is_virtual_hardware=is_vm,
            is_canvas_manipulated=canvas.noise_detected,
            anomalies=anomalies
        )