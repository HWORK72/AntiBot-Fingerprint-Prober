import hashlib
import struct
from typing import Any
from hpack import Decoder
from pydantic import BaseModel, Field
from core.logger import logger

H2_FRAME_DATA: int = 0x00
H2_FRAME_HEADERS: int = 0x01
H2_FRAME_PRIORITY: int = 0x02
H2_FRAME_RST_STREAM: int = 0x03
H2_FRAME_SETTINGS: int = 0x04
H2_FRAME_PUSH_PROMISE: int = 0x05
H2_FRAME_PING: int = 0x06
H2_FRAME_GOAWAY: int = 0x07
H2_FRAME_WINDOW_UPDATE: int = 0x08
H2_FRAME_CONTINUATION: int = 0x09

H2_FLAG_END_STREAM: int = 0x01
H2_FLAG_END_HEADERS: int = 0x04
H2_FLAG_PADDED: int = 0x08
H2_FLAG_PRIORITY: int = 0x20


class H2Fingerprint(BaseModel):
    akamai_fingerprint: str = Field(description="Akamai H2 raw fingerprint string")
    akamai_hash: str = Field(description="Akamai H2 MD5 hash")
    ja4h: str = Field(description="JA4H HTTP client fingerprint")
    settings: dict[int, int] = Field(default_factory=dict)
    window_update_increment: int | None = Field(default=None)
    priority_spec: str | None = Field(default=None)
    pseudo_headers_order: list[str] = Field(default_factory=list)
    regular_headers_order: list[str] = Field(default_factory=list)
    all_headers: dict[str, str] = Field(default_factory=dict)


class HTTP2FrameParser:

    @classmethod
    def parse_stream(cls, raw_bytes: bytes) -> H2Fingerprint | None:
        try:
            offset: int = 0
            total_len: int = len(raw_bytes)

            client_preface: bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            if raw_bytes.startswith(client_preface):
                offset += len(client_preface)

            settings_dict: dict[int, int] = {}
            window_update_val: int | None = None
            priority_val: str | None = None
            raw_headers_block: bytearray = bytearray()
            stream_headers_ended: bool = False

            while offset + 9 <= total_len:
                length_bytes: bytes = b"\x00" + raw_bytes[offset:offset + 3]
                frame_len: int = struct.unpack("!I", length_bytes)[0]
                frame_type: int = raw_bytes[offset + 3]
                frame_flags: int = raw_bytes[offset + 4]
                stream_id: int = struct.unpack("!I", raw_bytes[offset + 5:offset + 9])[0] & 0x7FFFFFFF

                offset += 9

                if offset + frame_len > total_len:
                    break

                payload: bytes = raw_bytes[offset:offset + frame_len]
                offset += frame_len

                if frame_type == H2_FRAME_SETTINGS and stream_id == 0:
                    for i in range(0, frame_len, 6):
                        if i + 6 <= frame_len:
                            param_id, param_val = struct.unpack("!HI", payload[i:i + 6])
                            settings_dict[param_id] = param_val

                elif frame_type == H2_FRAME_WINDOW_UPDATE:
                    if frame_len >= 4:
                        increment: int = struct.unpack("!I", payload[:4])[0] & 0x7FFFFFFF
                        if window_update_val is None:
                            window_update_val = increment

                elif frame_type == H2_FRAME_PRIORITY:
                    if frame_len >= 5:
                        dep_stream_id, weight = struct.unpack("!IB", payload[:5])
                        exclusive: int = (dep_stream_id >> 31) & 0x01
                        dep_id: int = dep_stream_id & 0x7FFFFFFF
                        priority_val = f"{dep_id}:{exclusive}:{weight + 1}"

                elif frame_type == H2_FRAME_HEADERS:
                    h_offset: int = 0
                    pad_length: int = 0

                    if frame_flags & H2_FLAG_PADDED:
                        pad_length = payload[h_offset]
                        h_offset += 1

                    if frame_flags & H2_FLAG_PRIORITY:
                        dep_stream_id, weight = struct.unpack("!IB", payload[h_offset:h_offset + 5])
                        exclusive = (dep_stream_id >> 31) & 0x01
                        dep_id = dep_stream_id & 0x7FFFFFFF
                        priority_val = f"{dep_id}:{exclusive}:{weight + 1}"
                        h_offset += 5

                    end_block: int = frame_len - pad_length
                    if end_block > h_offset:
                        raw_headers_block.extend(payload[h_offset:end_block])

                    if frame_flags & H2_FLAG_END_HEADERS:
                        stream_headers_ended = True

                elif frame_type == H2_FRAME_CONTINUATION:
                    raw_headers_block.extend(payload)
                    if frame_flags & H2_FLAG_END_HEADERS:
                        stream_headers_ended = True

            pseudo_order: list[str] = []
            regular_order: list[str] = []
            headers_map: dict[str, str] = {}

            if raw_headers_block:
                hpack_decoder: Decoder = Decoder()
                decoded_headers: list[tuple[Any, Any]] = hpack_decoder.decode(bytes(raw_headers_block))

                for name_raw, val_raw in decoded_headers:
                    name_str: str = (
                        name_raw.decode("utf-8", errors="ignore")
                        if isinstance(name_raw, bytes)
                        else str(name_raw)
                    ).lower()

                    val_str: str = (
                        val_raw.decode("utf-8", errors="ignore")
                        if isinstance(val_raw, bytes)
                        else str(val_raw)
                    )

                    headers_map[name_str] = val_str

                    if name_str.startswith(":"):
                        pseudo_order.append(name_str)
                    else:
                        regular_order.append(name_str)

            settings_str_elements: list[str] = [f"{k}:{v}" for k, v in settings_dict.items()]
            settings_formatted: str = ";".join(settings_str_elements) if settings_str_elements else "0"

            window_update_formatted: str = str(window_update_val) if window_update_val is not None else "0"
            priority_formatted: str = priority_val if priority_val is not None else "0"

            pseudo_shorthand_map: dict[str, str] = {
                ":method": "m",
                ":path": "p",
                ":authority": "a",
                ":scheme": "s",
                ":status": "t"
            }
            pseudo_encoded: list[str] = [pseudo_shorthand_map.get(h, h.lstrip(":")) for h in pseudo_order]
            pseudo_formatted: str = ",".join(pseudo_encoded) if pseudo_encoded else "0"

            akamai_str: str = f"{settings_formatted}|{window_update_formatted}|{priority_formatted}|{pseudo_formatted}"
            akamai_hash: str = hashlib.md5(akamai_str.encode("utf-8")).hexdigest()

            method_val: str = headers_map.get(":method", "ge").upper()[:2]
            h2_version_tag: str = "20"
            cookie_tag: str = "c" if "cookie" in headers_map else "n"
            referer_tag: str = "r" if "referer" in headers_map else "n"
            num_headers_str: str = f"{min(len(headers_map), 99):02d}"

            ja4h_a: str = f"{method_val}{h2_version_tag}{cookie_tag}{referer_tag}{num_headers_str}"

            regular_sorted: list[str] = sorted(regular_order)
            reg_headers_str: str = ",".join(regular_sorted)
            ja4h_b: str = hashlib.sha256(reg_headers_str.encode("utf-8")).hexdigest()[:12] if regular_sorted else "000000000000"

            cookie_names: list[str] = []
            if "cookie" in headers_map:
                raw_cookie: str = headers_map["cookie"]
                for cookie_part in raw_cookie.split(";"):
                    cookie_clean: str = cookie_part.strip()
                    if "=" in cookie_clean:
                        cookie_names.append(cookie_clean.split("=", 1)[0])
                    elif cookie_clean:
                        cookie_names.append(cookie_clean)

            cookie_names.sort()
            cookies_str: str = ",".join(cookie_names)
            ja4h_c: str = hashlib.sha256(cookies_str.encode("utf-8")).hexdigest()[:12] if cookie_names else "000000000000"

            ja4h_fingerprint: str = f"{ja4h_a}_{ja4h_b}_{ja4h_c}"

            return H2Fingerprint(
                akamai_fingerprint=akamai_str,
                akamai_hash=akamai_hash,
                ja4h=ja4h_fingerprint,
                settings=settings_dict,
                window_update_increment=window_update_val,
                priority_spec=priority_val,
                pseudo_headers_order=pseudo_order,
                regular_headers_order=regular_order,
                all_headers=headers_map
            )

        except Exception as exc:
            logger.error(f"Непредвиденный сбой при декодировании HTTP/2 фреймов: {exc}", exc_info=True)
            return None