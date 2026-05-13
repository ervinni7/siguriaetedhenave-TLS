"""
generate_certs.py - Konfigurimi PKI për simulimin e SSL/TLS Handshake

Gjeneron:
  1. Root CA (i vetë-nënshkruar, RSA-2048)
  2. Certifikatë serveri (e nënshkruar nga CA, CN=localhost)
  3. Certifikatë klienti (e nënshkruar nga CA, CN=client.local)

Të gjithë skedarët ruhen në direktorinë  certs/ .

Përdorimi:
    python generate_certs.py
"""

import os
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

CERTS_DIR = "certs"
KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


# ─────────────────────────────────────────────────────────────
#  API Publike
# ─────────────────────────────────────────────────────────────

def generate_all() -> None:
    """Gjeneron certifikatat e CA, serverit dhe klientit dhe i ruan në disk."""
    os.makedirs(CERTS_DIR, exist_ok=True)

    _banner("Generating Root Certificate Authority (CA)")
    ca_key, ca_cert = _generate_ca()
    _save_key(ca_key, _path("ca.key"))
    _save_cert(ca_cert, _path("ca.crt"))
    print(f"   [✓] CA key  →  {_path('ca.key')}")
    print(f"   [✓] CA cert →  {_path('ca.crt')}")

    _banner("Generating Server Certificate")
    srv_key, srv_cert = _generate_entity_cert(
        ca_key, ca_cert,
        common_name="localhost",
        org="TLS Simulation Server",
        role="server",
    )
    _save_key(srv_key, _path("server.key"))
    _save_cert(srv_cert, _path("server.crt"))
    print(f"   [✓] Server key  →  {_path('server.key')}")
    print(f"   [✓] Server cert →  {_path('server.crt')}")

    _banner("Generating Client Certificate")
    cli_key, cli_cert = _generate_entity_cert(
        ca_key, ca_cert,
        common_name="client.local",
        org="TLS Simulation Client",
        role="client",
    )
    _save_key(cli_key, _path("client.key"))
    _save_cert(cli_cert, _path("client.crt"))
    print(f"   [✓] Client key  →  {_path('client.key')}")
    print(f"   [✓] Client cert →  {_path('client.crt')}\n")

    print("All certificates generated successfully.\n")


def load_key(path: str):
    """Ngarkon një çelës privat të koduar në PEM nga skedari."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_cert(path: str):
    """Ngarkon një certifikatë X.509 të koduar në PEM nga skedari."""
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def certs_exist() -> bool:
    """Kthen True nëse të gjithë skedarët e certifikatave ekzistojnë tashmë."""
    files = ["ca.key", "ca.crt", "server.key", "server.crt", "client.key", "client.crt"]
    return all(os.path.exists(_path(f)) for f in files)


# ─────────────────────────────────────────────────────────────
#  Funksione Private Ndihmëse
# ─────────────────────────────────────────────────────────────

def _generate_ca():
    """Krijon një certifikatë Root CA të vetë-nënshkruar."""
    key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE)

    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Pristina"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TLS Simulation Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "TLS Sim Root CA"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)           # i vetë-nënshkruar
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _generate_entity_cert(ca_key, ca_cert, common_name: str, org: str, role: str):
    """
    Gjeneron një certifikatë end-entity të nënshkruar nga CA-ja e dhënë.
    role duhet të jetë 'server' ose 'client'.
    """
    key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Pristina"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    eku_oid = (
        ExtendedKeyUsageOID.SERVER_AUTH
        if role == "server"
        else ExtendedKeyUsageOID.CLIENT_AUTH
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([eku_oid]), critical=False
        )
    )

    # Serveri merr një SubjectAlternativeName për localhost
    if role == "server":
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )

    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _save_key(key, path: str) -> None:
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))


def _save_cert(cert, path: str) -> None:
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _path(filename: str) -> str:
    return os.path.join(CERTS_DIR, filename)


def _banner(msg: str) -> None:
    print(f"\n[*] {msg}...")


# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if certs_exist():
        print("[i] Certificates already exist in certs/. Regenerating...\n")
    generate_all()