import datetime
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from core.logger import logger

CERTS_DIR: Path = Path(__file__).resolve().parent.parent / "certs"
CERT_FILE: Path = CERTS_DIR / "cert.pem"
KEY_FILE: Path = CERTS_DIR / "key.pem"


def ensure_ssl_certificates() -> tuple[Path, Path]:
    try:
        CERTS_DIR.mkdir(parents=True, exist_ok=True)

        if CERT_FILE.exists() and KEY_FILE.exists():
            return CERT_FILE, KEY_FILE

        logger.info("Генерация локального самоподписанного SSL-сертификата для HTTPS/TLS инспектора...")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "DevLab"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AntiBot Prober"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        KEY_FILE.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        logger.info(f"SSL-сертификаты сгенерированы: {CERT_FILE} и {KEY_FILE}")

        return CERT_FILE, KEY_FILE

    except Exception as exc:
        logger.critical(f"Сбой при создании SSL-сертификатов: {exc}", exc_info=True)
        raise exc