from pathlib import Path
from typing import Any
import lupa
from lupa import LuaRuntime
from pydantic import BaseModel, Field
from core.logger import logger
from network.tls_parser import TLSFingerprint

LUA_DIR: Path = Path(__file__).resolve().parent.parent / "lua_engine"


class LuaFinding(BaseModel):
    rule_id: str
    detail: str


class LuaEvaluationResult(BaseModel):
    tls_profile: str = Field(default="NOT_EVALUATED")
    findings: list[LuaFinding] = Field(default_factory=list)
    engine_active: bool = Field(default=False)


class LuaRuleEngine:

    def __init__(self) -> None:
        self._lua: LuaRuntime | None = None
        self._heuristics_module: Any = None
        self._is_ready: bool = False
        self._initialize()

    def _initialize(self) -> None:
        try:
            sig_path: Path = LUA_DIR / "signatures.lua"
            heur_path: Path = LUA_DIR / "heuristics.lua"

            if not sig_path.exists() or not heur_path.exists():
                logger.warning(f"Lua rule scripts not found in {LUA_DIR}. Lua edge engine disabled.")
                return

            runtime: LuaRuntime = LuaRuntime(
                unpack_returned_tuples=True,
                register_eval=False,
                register_builtins=False
            )

            sig_code: str = sig_path.read_text(encoding="utf-8")
            heur_code: str = heur_path.read_text(encoding="utf-8")

            sig_module: Any = runtime.execute(sig_code)
            runtime.globals().SignatureModule = sig_module

            heur_module: Any = runtime.execute(heur_code)
            runtime.globals().HeuristicsModule = heur_module

            self._lua = runtime
            self._heuristics_module = heur_module
            self._is_ready = True
            logger.info("Embedded Lua 5.4 L7 heuristic & signature engine loaded successfully.")

        except Exception as exc:
            logger.error(f"Failed to initialize Lua rule engine: {exc}", exc_info=True)
            self._is_ready = False

    @classmethod
    def _lua_to_python(cls, value: Any) -> Any:
        if lupa.lua_type(value) != "table":
            return value
        keys: list[Any] = list(value.keys())
        if not keys:
            return []
        if all(isinstance(k, int) for k in keys):
            return [cls._lua_to_python(value[k]) for k in sorted(keys)]
        return {str(k): cls._lua_to_python(value[k]) for k in keys}

    def evaluate(
        self,
        claimed_ua: str,
        headers: dict[str, str] | None = None,
        tls: TLSFingerprint | None = None,
        is_websocket: bool = False,
        webgl_renderer: str = ""
    ) -> LuaEvaluationResult:
        if not self._is_ready or self._lua is None or self._heuristics_module is None:
            return LuaEvaluationResult(engine_active=False)

        try:
            tls_dict: dict[str, Any] | None = None
            if tls is not None:
                tls_dict = {
                    "ja3": tls.ja3,
                    "ja4": tls.ja4,
                    "is_grease_present": tls.is_grease_present,
                    "cipher_count": len(tls.cipher_suites),
                    "extension_count": len(tls.extensions),
                    "has_h2_alpn": "h2" in tls.alpn_protocols
                }

            context_payload: dict[str, Any] = {
                "claimed_ua": claimed_ua,
                "headers": headers if headers is not None else {},
                "tls": tls_dict,
                "is_websocket": is_websocket,
                "webgl_renderer": webgl_renderer
            }

            lua_ctx: Any = self._lua.table_from(context_payload, recursive=True)
            raw_result: Any = self._heuristics_module.evaluate_l7(lua_ctx)
            parsed: Any = self._lua_to_python(raw_result)

            if not isinstance(parsed, dict):
                return LuaEvaluationResult(engine_active=True)

            findings_list: list[LuaFinding] = []
            raw_findings: Any = parsed.get("findings", [])
            if isinstance(raw_findings, list):
                for item in raw_findings:
                    if isinstance(item, dict) and "rule_id" in item and "detail" in item:
                        findings_list.append(
                            LuaFinding(
                                rule_id=str(item["rule_id"]),
                                detail=str(item["detail"])
                            )
                        )

            return LuaEvaluationResult(
                tls_profile=str(parsed.get("tls_profile", "UNKNOWN")),
                findings=findings_list,
                engine_active=True
            )

        except Exception as exc:
            logger.error(f"Runtime error inside Lua heuristic evaluation: {exc}", exc_info=True)
            return LuaEvaluationResult(engine_active=False)


lua_rule_engine: LuaRuleEngine = LuaRuleEngine()