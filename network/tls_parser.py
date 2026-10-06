import hashlib
import struct
from pydantic import BaseModel, Field
from core.logger import logger

GREASE_VALUES: set[int] = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
    0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA
}


class TLSFingerprint(BaseModel):
    ja3: str = Field(description="JA3 MD5 hash")
    ja3_raw: str = Field(description="Raw string used for JA3 calculation")
    ja4: str = Field(description="JA4 standard fingerprint")
    ja4_raw: str = Field(description="Raw string components for JA4")
    sni: str | None = Field(default=None, description="Server Name Indication hostname")
    client_version: int = Field(description="TLS record version or client hello version")
    cipher_suites: list[int] = Field(default_factory=list)
    extensions: list[int] = Field(default_factory=list)
    supported_groups: list[int] = Field(default_factory=list)
    ec_point_formats: list[int] = Field(default_factory=list)
    signature_algorithms: list[int] = Field(default_factory=list)
    alpn_protocols: list[str] = Field(default_factory=list)
    is_grease_present: bool = Field(default=False)


class TLSClientHelloParser:

    @staticmethod
    def is_grease(val: int) -> bool:
        return val in GREASE_VALUES or (val & 0x0F0F == 0x0A0A and ((val >> 8) & 0xFF) == (val & 0xFF))

    @classmethod
    def parse(cls, raw_bytes: bytes) -> TLSFingerprint | None:
        try:
            if len(raw_bytes) < 5:
                return None

            content_type, legacy_version, length = struct.unpack("!BHH", raw_bytes[:5])
            if content_type != 0x16:
                return None

            payload: bytes = raw_bytes[5:5 + length]
            if len(payload) < 4:
                return None

            handshake_type: int = payload[0]
            if handshake_type != 0x01:
                return None

            handshake_len: int = struct.unpack("!I", b"\x00" + payload[1:4])[0]
            handshake_body: bytes = payload[4:4 + handshake_len]

            offset: int = 0
            if len(handshake_body) < 2 + 32 + 1:
                return None

            client_version: int = struct.unpack("!H", handshake_body[offset:offset + 2])[0]
            offset += 2
            offset += 32

            session_id_len: int = handshake_body[offset]
            offset += 1 + session_id_len

            if offset + 2 > len(handshake_body):
                return None

            cipher_suites_len: int = struct.unpack("!H", handshake_body[offset:offset + 2])[0]
            offset += 2

            raw_ciphers: list[int] = []
            grease_detected: bool = False

            for i in range(0, cipher_suites_len, 2):
                cs: int = struct.unpack("!H", handshake_body[offset + i:offset + i + 2])[0]
                if cls.is_grease(cs):
                    grease_detected = True
                else:
                    raw_ciphers.append(cs)

            offset += cipher_suites_len

            if offset >= len(handshake_body):
                return None

            compression_methods_len: int = handshake_body[offset]
            offset += 1 + compression_methods_len

            raw_extensions: list[int] = []
            supported_groups: list[int] = []
            ec_point_formats: list[int] = []
            sig_algs: list[int] = []
            alpn_protocols: list[str] = []
            sni: str | None = None
            supported_tls_versions: list[int] = []

            if offset + 2 <= len(handshake_body):
                extensions_total_len: int = struct.unpack("!H", handshake_body[offset:offset + 2])[0]
                offset += 2
                ext_end: int = offset + extensions_total_len

                while offset + 4 <= ext_end and offset + 4 <= len(handshake_body):
                    ext_type, ext_len = struct.unpack("!HH", handshake_body[offset:offset + 4])
                    offset += 4
                    ext_data: bytes = handshake_body[offset:offset + ext_len]
                    offset += ext_len

                    if cls.is_grease(ext_type):
                        grease_detected = True
                        continue

                    raw_extensions.append(ext_type)

                    if ext_type == 0x0000:
                        if len(ext_data) >= 5:
                            sni_list_len: int = struct.unpack("!H", ext_data[0:2])[0]
                            sni_offset: int = 2
                            while sni_offset + 3 <= len(ext_data):
                                name_type: int = ext_data[sni_offset]
                                name_len: int = struct.unpack("!H", ext_data[sni_offset + 1:sni_offset + 3])[0]
                                sni_offset += 3
                                if name_type == 0x00 and sni_offset + name_len <= len(ext_data):
                                    sni = ext_data[sni_offset:sni_offset + name_len].decode("utf-8", errors="ignore")
                                    break
                                sni_offset += name_len

                    elif ext_type == 0x000A:
                        if len(ext_data) >= 2:
                            groups_len: int = struct.unpack("!H", ext_data[:2])[0]
                            for g_idx in range(2, 2 + groups_len, 2):
                                if g_idx + 2 <= len(ext_data):
                                    group_val: int = struct.unpack("!H", ext_data[g_idx:g_idx + 2])[0]
                                    if not cls.is_grease(group_val):
                                        supported_groups.append(group_val)
                                    else:
                                        grease_detected = True

                    elif ext_type == 0x000B:
                        if len(ext_data) >= 1:
                            ec_len: int = ext_data[0]
                            for ec_idx in range(1, 1 + ec_len):
                                if ec_idx < len(ext_data):
                                    ec_point_formats.append(ext_data[ec_idx])

                    elif ext_type == 0x000D:
                        if len(ext_data) >= 2:
                            sig_len: int = struct.unpack("!H", ext_data[:2])[0]
                            for s_idx in range(2, 2 + sig_len, 2):
                                if s_idx + 2 <= len(ext_data):
                                    sig_val: int = struct.unpack("!H", ext_data[s_idx:s_idx + 2])[0]
                                    sig_algs.append(sig_val)

                    elif ext_type == 0x0010:
                        if len(ext_data) >= 2:
                            alpn_total_len: int = struct.unpack("!H", ext_data[:2])[0]
                            a_offset: int = 2
                            while a_offset < 2 + alpn_total_len and a_offset < len(ext_data):
                                str_len: int = ext_data[a_offset]
                                a_offset += 1
                                if a_offset + str_len <= len(ext_data):
                                    alpn_str: str = ext_data[a_offset:a_offset + str_len].decode("utf-8", errors="ignore")
                                    alpn_protocols.append(alpn_str)
                                    a_offset += str_len

                    elif ext_type == 0x002B:
                        if len(ext_data) >= 1:
                            vers_len: int = ext_data[0]
                            for v_idx in range(1, 1 + vers_len, 2):
                                if v_idx + 2 <= len(ext_data):
                                    v_val: int = struct.unpack("!H", ext_data[v_idx:v_idx + 2])[0]
                                    if not cls.is_grease(v_val):
                                        supported_tls_versions.append(v_val)
                                    else:
                                        grease_detected = True

            ja3_str: str = (
                f"{client_version},"
                f"{'-'.join(str(c) for c in raw_ciphers)},"
                f"{'-'.join(str(e) for e in raw_extensions)},"
                f"{'-'.join(str(g) for g in supported_groups)},"
                f"{'-'.join(str(p) for p in ec_point_formats)}"
            )
            ja3_hash: str = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()

            protocol_char: str = "t"
            if 0x0304 in supported_tls_versions:
                tls_ver_str: str = "13"
            elif client_version == 0x0303:
                tls_ver_str: str = "12"
            elif client_version == 0x0302:
                tls_ver_str: str = "11"
            elif client_version == 0x0301:
                tls_ver_str: str = "10"
            else:
                tls_ver_str: str = "00"

            sni_indicator: str = "d" if sni else "i"
            ciphers_count_str: str = f"{min(len(raw_ciphers), 99):02d}"

            ja4_exts: list[int] = [ext for ext in raw_extensions if ext not in (0x0000, 0x0010)]
            ext_count_str: str = f"{min(len(ja4_exts), 99):02d}"

            if alpn_protocols:
                first_alpn: str = alpn_protocols[0]
                alpn_part: str = f"{first_alpn[0]}{first_alpn[-1]}"
            else:
                alpn_part = "00"

            ja4_a: str = f"{protocol_char}{tls_ver_str}{sni_indicator}{ciphers_count_str}{ext_count_str}{alpn_part}"

            sorted_ciphers_hex: list[str] = [f"{c:04x}" for c in sorted(raw_ciphers)]
            ciphers_payload: str = ",".join(sorted_ciphers_hex)
            ja4_b: str = hashlib.sha256(ciphers_payload.encode("utf-8")).hexdigest()[:12] if sorted_ciphers_hex else "000000000000"

            sorted_exts_hex: list[str] = [f"{e:04x}" for e in sorted(ja4_exts)]
            exts_payload: str = ",".join(sorted_exts_hex)
            if sig_algs:
                sigs_payload: str = "_".join(f"{s:04x}" for s in sig_algs)
                exts_payload = f"{exts_payload}_{sigs_payload}"

            ja4_c: str = hashlib.sha256(exts_payload.encode("utf-8")).hexdigest()[:12] if exts_payload else "000000000000"

            ja4_fingerprint: str = f"{ja4_a}_{ja4_b}_{ja4_c}"
            ja4_raw_str: str = f"{ja4_a}_{ciphers_payload}_{exts_payload}"

            return TLSFingerprint(
                ja3=ja3_hash,
                ja3_raw=ja3_str,
                ja4=ja4_fingerprint,
                ja4_raw=ja4_raw_str,
                sni=sni,
                client_version=client_version,
                cipher_suites=raw_ciphers,
                extensions=raw_extensions,
                supported_groups=supported_groups,
                ec_point_formats=ec_point_formats,
                signature_algorithms=sig_algs,
                alpn_protocols=alpn_protocols,
                is_grease_present=grease_detected
            )

        except Exception as exc:
            logger.error(f"Непредвиденный сбой при парсинге TLS Client Hello: {exc}", exc_info=True)
            return None