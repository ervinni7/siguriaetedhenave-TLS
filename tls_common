"""
tls_common.py - Shared utilities for the SSL/TLS Handshake Simulation
Includes: message types, socket protocol, crypto helpers, logging setup
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
#  TLS Handshake Message Types
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
#  Supported Cipher Suites (ordered by preference)
# ─────────────────────────────────────────────
CIPHER_SUITES = [
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
]

TLS_VERSION = "TLS 1.3 (simulation)"

# ─────────────────────────────────────────────
#  Logger Setup
# ─────────────────────────────────────────────
def setup_logger(name: str, level=logging.DEBUG) -> logging.Logger:
    """
    Configure a logger that writes to both console and a .log file.
    Console shows INFO+; file captures everything (DEBUG+).
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Avoid duplicate handlers on re-import
    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "%(asctime)s [%(name)-8s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler – captures all debug details
    fh = logging.FileHandler(f"{name.lower()}.log", mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


# ─────────────────────────────────────────────
#  Length-Prefixed JSON Socket Protocol
# ─────────────────────────────────────────────
def send_message(sock: socket.socket, msg_type: str, payload: dict = None) -> None:
    """
    Send a TLS simulation message over a TCP socket.
    Wire format: [4-byte big-endian length][UTF-8 JSON body]
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
    Receive a length-prefixed JSON message from the socket.
    Raises ConnectionError if the connection is closed mid-read.
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
    """Read exactly n bytes; returns b'' on clean close."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


# ─────────────────────────────────────────────
#  Base64 Helpers
# ─────────────────────────────────────────────
def b64_encode(data) -> str:
    """Encode bytes (or str) as URL-safe base64 string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def b64_decode(data: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(data)


# ─────────────────────────────────────────────
#  Misc Helpers
# ─────────────────────────────────────────────
def sha256_hex(data) -> str:
    """Return SHA-256 hex digest of data (bytes or str)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def cert_not_before(cert):
    """Return timezone-aware not_valid_before datetime (handles old & new API)."""
    try:
        return cert.not_valid_before_utc
    except AttributeError:
        return cert.not_valid_before.replace(tzinfo=timezone.utc)


def cert_not_after(cert):
    """Return timezone-aware not_valid_after datetime (handles old & new API)."""
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=timezone.utc)