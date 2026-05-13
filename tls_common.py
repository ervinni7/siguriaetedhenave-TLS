"""
tls_common.py - Funksione të përbashkëta për simulimin e SSL/TLS Handshake
Përfshin: tipet e mesazheve, protokollin e socket-it, ndihmës kriptografikë, konfigurimin e logimit
"""

import json
import struct
import socket
import base64
import hashlib
import os
import logging
from datetime import datetime, timezone


# ─────────────────────────────────────────────
#  Tipet e Mesazheve të TLS Handshake
# ─────────────────────────────────────────────
CLIENT_HELLO       = "CLIENT_HELLO"
SERVER_HELLO       = "SERVER_HELLO"
CERTIFICATE        = "CERTIFICATE"
SERVER_KEY_EXCHANGE = "SERVER_KEY_EXCHANGE"
CERTIFICATE_REQUEST = "CERTIFICATE_REQUEST"
SERVER_HELLO_DONE  = "SERVER_HELLO_DONE"
CLIENT_CERTIFICATE = "CLIENT_CERTIFICATE"
CLIENT_KEY_EXCHANGE = "CLIENT_KEY_EXCHANGE"
CERTIFICATE_VERIFY = "CERTIFICATE_VERIFY"
CHANGE_CIPHER_SPEC = "CHANGE_CIPHER_SPEC"
FINISHED           = "FINISHED"
APPLICATION_DATA   = "APPLICATION_DATA"
ALERT              = "ALERT"

# ─────────────────────────────────────────────
#  Cipher Suites të Mbështetura (sipas preferencës)
# ─────────────────────────────────────────────
CIPHER_SUITES = [
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
]

TLS_VERSION = "TLS 1.3 (simulation)"

# ─────────────────────────────────────────────
#  Konfigurimi i Logger-it
# ─────────────────────────────────────────────
def setup_logger(name: str, level=logging.DEBUG) -> logging.Logger:
    """
    Konfiguron një logger që shkruan si në konsolë, ashtu edhe në një skedar .log.
    Konsola shfaq INFO+; skedari kap gjithçka (DEBUG+).
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Shmang handler-at e dyfishtë gjatë ri-importit
    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "%(asctime)s [%(name)-8s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler – kap të gjitha detajet e debug-ut
    fh = logging.FileHandler(f"{name.lower()}.log", mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


# ─────────────────────────────────────────────
#  Protokolli Socket JSON me Prefiks-Gjatësi
# ─────────────────────────────────────────────
def send_message(sock: socket.socket, msg_type: str, payload: dict = None) -> None:
    """
    Dërgon një mesazh të simulimit TLS përmes një socket-i TCP.
    Formati i tubacionit: [4-bajt big-endian gjatësi][trup JSON UTF-8]
    """
    envelope = {
        "type": msg_type,
        "timestamp": datetime.utcnow().isoformat(),
        "payload": payload or {},
    }
    body = json.dumps(envelope).encode("utf-8")
    header = struct.pack(">I", len(body))
    sock.sendall(header + body)


def recv_message(sock: socket.socket) -> dict:
    """
    Pranon një mesazh JSON me prefiks-gjatësi nga socket-i.
    Ngre ConnectionError nëse lidhja mbyllet gjatë leximit.
    """
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        raise ConnectionError("Connection closed unexpectedly (no length header)")
    length = struct.unpack(">I", raw_len)[0]

    raw_body = _recv_exact(sock, length)
    if not raw_body:
        raise ConnectionError("Connection closed unexpectedly (incomplete body)")

    return json.loads(raw_body.decode("utf-8"))


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Lexon saktësisht n bajte; kthen b'' në mbyllje të pastër."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


# ─────────────────────────────────────────────
#  Ndihmës Base64
# ─────────────────────────────────────────────
def b64_encode(data) -> str:
    """Kodon bajte (ose string) si string base64 URL-safe."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def b64_decode(data: str) -> bytes:
    """Dekodon një string base64 në bajte."""
    return base64.b64decode(data)


# ─────────────────────────────────────────────
#  Ndihmës të Ndryshëm
# ─────────────────────────────────────────────
def sha256_hex(data) -> str:
    """Kthen digjestin SHA-256 në hex të të dhënave (bajte ose string)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def cert_not_before(cert):
    """Kthen datetime not_valid_before me timezone (trajton API të vjetër & të ri)."""
    try:
        return cert.not_valid_before_utc
    except AttributeError:
        return cert.not_valid_before.replace(tzinfo=timezone.utc)


def cert_not_after(cert):
    """Kthen datetime not_valid_after me timezone (trajton API të vjetër & të ri)."""
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=timezone.utc)