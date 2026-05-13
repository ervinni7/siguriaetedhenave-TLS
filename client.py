"""
client.py - Klient simulues i SSL/TLS Handshake

Simulon një klient TLS i cili:
  • Inicion handshake-un me ClientHello
  • Verifikon certifikatën e serverit (vlefshmërinë, besimin e CA-së, hostname-in)
  • Kryen shkëmbimin e çelësave ECDHE (X25519)
  • Paraqet certifikatën e tij të klientit
  • Enkripton dhe dekripton të dhënat e aplikacionit me AES-256-GCM

Përdorimi:
    python client.py
"""

import os
import sys
import socket
import hashlib
import datetime

from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tls_common import (
    setup_logger, send_message, recv_message,
    b64_encode, b64_decode, cert_not_before, cert_not_after,
    CLIENT_HELLO, SERVER_HELLO, CERTIFICATE, SERVER_KEY_EXCHANGE,
    CERTIFICATE_REQUEST, SERVER_HELLO_DONE, CLIENT_CERTIFICATE,
    CLIENT_KEY_EXCHANGE, CERTIFICATE_VERIFY, CHANGE_CIPHER_SPEC,
    FINISHED, APPLICATION_DATA, ALERT,
    CIPHER_SUITES, TLS_VERSION,
)
from generate_certs import load_key, load_cert, generate_all, certs_exist

HOST = "127.0.0.1"
PORT = 8443

SEP  = "─" * 58
SEP2 = "═" * 58


class TLSClient:
    """Klient i simuluar TLS me handshake të plotë dhe komunikim të sigurt."""

    def __init__(self):
        self.logger = setup_logger("CLIENT")

        if not certs_exist():
            print("[i] Certificates not found – generating now...\n")
            generate_all()

        self.client_key  = load_key("certs/client.key")
        self.client_cert = load_cert("certs/client.crt")
        self.ca_cert     = load_cert("certs/ca.crt")

        self.session_key  = None
        self.cipher_suite = None

    
    #  Pika e Hyrjes
        def connect(self) -> None:
        print(SEP2)
        print("    SSL/TLS Handshake Simulation — CLIENT")
        print(SEP2)
        print("\n  Welcome to the SSL/TLS Handshake Simulation Client.")
        print(f"\n  [CLIENT] Attempting to connect to {HOST}:{PORT}...")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                self.logger.info(f"TCP connection established to {HOST}:{PORT}")
                print(f"  [CLIENT] ✓ TCP connection established.\n")
                self._perform_handshake(s)
                self._secure_communication(s)
        except ConnectionRefusedError:
            print(
                f"\n  [CLIENT] ✗ Connection refused on {HOST}:{PORT}.\n"
                "  Make sure server.py is running first.\n"
            )
            sys.exit(1)
        except Exception as exc:
            self.logger.error(f"Fatal error: {exc}")
            print(f"\n  [CLIENT] ✗ Error: {exc}")
            sys.exit(1)

    #  TLS Handshake (11 Hapa)
    def _perform_handshake(self, conn: socket.socket) -> None:
        self.logger.info("=== Initiating SSL/TLS Handshake ===")
        print(f"  {SEP}")
        print("   HANDSHAKE PHASE")
        print(f"  {SEP}")

        # ── Hapi 1: Dërgo ClientHello ────────
        client_random = os.urandom(32)
        session_id    = b64_encode(os.urandom(16))

        send_message(conn, CLIENT_HELLO, {
            "tls_version": TLS_VERSION,
            "random":      b64_encode(client_random),
            "session_id":  session_id,
            "cipher_suites": CIPHER_SUITES,
            "compression_methods": ["null"],
            "extensions": {
                "server_name":         HOST,
                "supported_groups":    ["x25519", "secp256r1"],
                "signature_algorithms": ["rsa_pkcs1_sha256", "rsa_pkcs1_sha384"],
            },
        })
        self.logger.info(f"[Step 1] ClientHello sent | suites={CIPHER_SUITES}")
        print(f"\n  [→] Step  1/11 · ClientHello sent")
        print(f"       TLS Version   : {TLS_VERSION}")
        print(f"       Cipher Suites : {', '.join(CIPHER_SUITES)}")
        print(f"       Server Name   : {HOST}")

        # ── Hapi 2: Prano ServerHello ────────────────────────────────────
        msg = recv_message(conn)
        self._assert_type(msg, SERVER_HELLO)
        sh = msg["payload"]
        server_random     = b64_decode(sh["random"])
        self.cipher_suite = sh["cipher_suite"]

        self.logger.info(f"[Step 2] ServerHello received | cipher={self.cipher_suite}")
        print(f"\n  [←] Step  2/11 · ServerHello received")
        print(f"       Selected Suite : {self.cipher_suite}")
        print(f"       Session ID     : {sh['session_id'][:20]}...")

        # ── Hapi 3: Prano Certifikatën ───────────────────────────────────
        msg = recv_message(conn)
        self._assert_type(msg, CERTIFICATE)
        cp = msg["payload"]
        server_cert = load_pem_x509_certificate(cp["certificate"].encode())

        self.logger.info("[Step 3] Server certificate received")
        print(f"\n  [←] Step  3/11 · Server Certificate received")
        srv_cn     = server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        srv_issuer = server_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        print(f"       Subject      : {srv_cn}")
        print(f"       Issued by    : {srv_issuer}")
        print(f"       Valid until  : {cert_not_after(server_cert).strftime('%Y-%m-%d')}")

        # Verifiko certifikatën
        print(f"\n  [*] Verifying server certificate...")
        self._verify_server_cert(server_cert)

        # ── Hapi 4: Prano ServerKeyExchange ──────────────────────────────
        msg = recv_message(conn)
        self._assert_type(msg, SERVER_KEY_EXCHANGE)
        ke = msg["payload"]
        srv_ecdh_bytes = b64_decode(ke["ecdh_public_key"])
        srv_ke_sig     = b64_decode(ke["signature"])

        # Verifiko se serveri ka nënshkruar çelësin e tij publik ECDH me çelësin e tij privat RSA
        sign_data = server_random + client_random + srv_ecdh_bytes
        try:
            server_cert.public_key().verify(
                srv_ke_sig, sign_data, padding.PKCS1v15(), hashes.SHA256()
            )
            self.logger.info("[Step 4] ServerKeyExchange signature verified")
            ske_status = "✓ Signature verified"
        except Exception as exc:
            self.logger.error(f"[Step 4] ServerKeyExchange signature INVALID: {exc}")
            raise ValueError(f"ServerKeyExchange signature invalid: {exc}")

        print(f"\n  [←] Step  4/11 · ServerKeyExchange received  ({ke['key_exchange_algorithm']})")
        print(f"       Server DH Pub  : {b64_encode(srv_ecdh_bytes)[:32]}...")
        print(f"       {ske_status}")

        # ── Hapi 5: Prano CertificateRequest ─────────────────────────────
        msg = recv_message(conn)
        self._assert_type(msg, CERTIFICATE_REQUEST)
        self.logger.info("[Step 5] CertificateRequest received")
        print(f"\n  [←] Step  5/11 · CertificateRequest received")
        print(f"       Types : {msg['payload']['certificate_types']}")

        # ── Hapi 6: Prano ServerHelloDone ────────────────────────────────
        msg = recv_message(conn)
        self._assert_type(msg, SERVER_HELLO_DONE)
        self.logger.info("[Step 6] ServerHelloDone received")
        print(f"\n  [←] Step  6/11 · ServerHelloDone received")

        # ── Hapi 7: Dërgo ClientCertificate ──────────────────────────────
        cert_pem = self.client_cert.public_bytes(serialization.Encoding.PEM).decode()
        cli_cn   = self.client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        send_message(conn, CLIENT_CERTIFICATE, {
            "certificate": cert_pem,
            "subject":     str(self.client_cert.subject),
        })
        self.logger.info(f"[Step 7] Client certificate sent | CN={cli_cn}")
        print(f"\n  [→] Step  7/11 · Client Certificate sent")
        print(f"       Subject      : {cli_cn}")

        # ── Hapi 8: Dërgo ClientKeyExchange ──────────────────────────────
        cli_ecdh_priv  = X25519PrivateKey.generate()
        cli_ecdh_pub   = cli_ecdh_priv.public_key()
        cli_ecdh_bytes = cli_ecdh_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        send_message(conn, CLIENT_KEY_EXCHANGE, {
            "ecdh_public_key": b64_encode(cli_ecdh_bytes),
        })

        # Llogarit sekretin e përbashkët ECDHE
        srv_ecdh_pub  = X25519PublicKey.from_public_bytes(srv_ecdh_bytes)
        shared_secret = cli_ecdh_priv.exchange(srv_ecdh_pub)

        # Nxirr çelësin simetrik të sesionit përmes HKDF-SHA256
        self.session_key = self._derive_session_key(
            shared_secret, client_random, server_random
        )

        self.logger.info("[Step 8] ClientKeyExchange sent | session key derived")
        print(f"\n  [→] Step  8/11 · ClientKeyExchange sent")
        print(f"       Client DH Pub  : {b64_encode(cli_ecdh_bytes)[:32]}...")
        print(f"       ✓ Shared secret computed via ECDHE-X25519")
        print(f"       ✓ Session key derived via HKDF-SHA256")

        # ── Hapi 9: Dërgo CertificateVerify ──────────────────────────────
        # Nënshkruaj një digest të të gjithë transkriptit të handshake-ut
        handshake_transcript = (
            client_random + server_random + cli_ecdh_bytes + srv_ecdh_bytes
        )
        cv_sig = self.client_key.sign(
            handshake_transcript, padding.PKCS1v15(), hashes.SHA256()
        )
        send_message(conn, CERTIFICATE_VERIFY, {
            "signature":   b64_encode(cv_sig),
            "signed_data": b64_encode(handshake_transcript),
            "algorithm":   "RSA-PKCS1v15-SHA256",
        })
        self.logger.info("[Step 9] CertificateVerify sent")
        print(f"\n  [→] Step  9/11 · CertificateVerify sent")
        print(f"       Algorithm      : RSA-PKCS1v15-SHA256")

        # ── Hapi 10: Dërgo ChangeCipherSpec + Finished ───────────────────
        send_message(conn, CHANGE_CIPHER_SPEC, {"message": "1"})
        self.logger.info("[Step 10a] ChangeCipherSpec sent")
        print(f"\n  [→] Step 10/11 · ChangeCipherSpec  (Client → Server)")

        cli_verify = hashlib.sha256(self.session_key + b"client finished").digest()
        send_message(conn, FINISHED, {"verify_data": b64_encode(cli_verify)})
        self.logger.info("[Step 10b] Client Finished sent")
        print(f"  [→]          · Finished sent       | verify={b64_encode(cli_verify)[:20]}...")

        # ── Hapi 11: Prano ChangeCipherSpec + Finished ───────────────────
        msg = recv_message(conn)
        self._assert_type(msg, CHANGE_CIPHER_SPEC)
        self.logger.info("[Step 11a] ChangeCipherSpec received from server")
        print(f"\n  [←] Step 11/11 · ChangeCipherSpec  (Server → Client)")

        msg = recv_message(conn)
        self._assert_type(msg, FINISHED)
        srv_verify = b64_decode(msg["payload"]["verify_data"])
        self.logger.info("[Step 11b] Server Finished received")
        print(f"  [←]          · Finished received   | verify={b64_encode(srv_verify)[:20]}...")

        # ── Handshake i Përfunduar ───────────────────────────────────────
        self.logger.info("=== Handshake Complete – Secure channel established ===")
        print(f"\n  {SEP}")
        print("   ✓ SSL/TLS HANDSHAKE SUCCESSFUL!")
        print("   ✓ Secure Communication Channel Established")
        print(f"   ✓ Cipher Suite : {self.cipher_suite}")
        print(f"   ✓ Session Key  : {b64_encode(self.session_key)[:24]}...")
        print(f"  {SEP}")

    #  Shkëmbimi i të Dhënave të Aplikacionit i Enkriptuar
    def _secure_communication(self, conn: socket.socket) -> None:
        print(f"\n  {SEP}")
        print("   SECURE APPLICATION DATA PHASE  (AES-256-GCM)")
        print(f"  {SEP}")

        aesgcm  = AESGCM(self.session_key)
        message = "Hello Server! This message is end-to-end encrypted with AES-256-GCM."
        nonce   = os.urandom(12)
        cipher  = aesgcm.encrypt(nonce, message.encode(), None)

        send_message(conn, APPLICATION_DATA, {
            "nonce":      b64_encode(nonce),
            "ciphertext": b64_encode(cipher),
        })
        self.logger.info(f"[APP] Sent encrypted message: {message!r}")
        print(f"\n  [→] Encrypted message sent to server")
        print(f"       Plaintext  : \"{message}\"")
        print(f"       Nonce      : {b64_encode(nonce)[:20]}...")
        print(f"       Ciphertext : {b64_encode(cipher)[:36]}...")

        # Prano përgjigjen e enkriptuar
        msg = recv_message(conn)
        if msg["type"] == APPLICATION_DATA:
            nonce2  = b64_decode(msg["payload"]["nonce"])
            cipher2 = b64_decode(msg["payload"]["ciphertext"])
            plain2  = aesgcm.decrypt(nonce2, cipher2, None).decode("utf-8")

            self.logger.info(f"[APP] Decrypted server response: {plain2!r}")
            print(f"\n  [←] Encrypted response received from server")
            print(f"       Ciphertext : {b64_encode(cipher2)[:36]}...")
            print(f"       Decrypted  : \"{plain2}\"")

        print(f"\n  {SEP2}")
        print("  ✓ Secure session complete.")
        print(f"  {SEP2}\n")

    #  Verifikimi i Certifikatës (3 kontrolle)
    def _verify_server_cert(self, cert) -> None:
        """
        Verifikon certifikatën X.509 të serverit:
          1. Periudhën e vlefshmërisë (jo e skaduar, jo ende e pavlefshme)
          2. Nënshkrimin nga një CA e besuar
          3. Hostname-in (Common Name duhet të përputhet me HOST)
        Ngre ValueError në çdo dështim.
        """
        errors = []
        now = datetime.datetime.now(datetime.timezone.utc)

        # ── Kontrolli 1: Periudha e vlefshmërisë ─────────────────────────
        if now < cert_not_before(cert):
            errors.append("Certificate is not yet valid")
        elif now > cert_not_after(cert):
            errors.append("Certificate has expired")
        else:
            self.logger.info("Cert check 1/3: validity period OK")
            print(f"       ✓ Validity period: OK")

        # ── Kontrolli 2: Nënshkrimi nga CA e besuar ──────────────────────
        try:
            self.ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            self.logger.info("Cert check 2/3: CA signature OK")
            print(f"       ✓ Signed by trusted CA")
        except Exception as exc:
            errors.append(f"Certificate signature invalid: {exc}")
            self.logger.error(f"Cert check 2/3 FAILED: {exc}")

        # ── Kontrolli 3: Hostname / Common Name ──────────────────────────
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if cn.lower() in (HOST.lower(), "localhost"):
                self.logger.info(f"Cert check 3/3: hostname OK (CN={cn})")
                print(f"       ✓ Hostname matches  (CN={cn})")
            else:
                errors.append(f"Hostname mismatch: expected '{HOST}', got '{cn}'")
                self.logger.error(f"Cert check 3/3 FAILED: hostname mismatch")
        except Exception as exc:
            errors.append(f"Cannot read CN: {exc}")

        if errors:
            for e in errors:
                print(f"       ✗ {e}")
            raise ValueError("Certificate verification failed:\n  " + "\n  ".join(errors))

        self.logger.info("Server certificate fully verified")
        print(f"       ✓ Server certificate is VALID and TRUSTED")

    #  Ndihmës Kriptografikë
    def _derive_session_key(
        self, shared_secret: bytes, client_random: bytes, server_random: bytes
    ) -> bytes:
        """Nxjerr një çelës sesioni 256-bit me HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=client_random + server_random,
            info=b"tls-simulation-session-key-v1",
        )
        return hkdf.derive(shared_secret)


    #  Funksione Ndihmëse
    @staticmethod
    def _assert_type(msg: dict, expected: str) -> None:
        if msg.get("type") != expected:
            raise ValueError(
                f"Protocol error: expected {expected}, got {msg.get('type')}"
            )


if __name__ == "__main__":
    client = TLSClient()
    client.connect()
