"""
server.py - Server simulues i SSL/TLS Handshake

Simulon një server real TLS i cili:
  • Kryen një handshake të plotë TLS me 11 hapa
  • Paraqet një certifikatë X.509 për verifikim nga klienti
  • Ekzekuton shkëmbimin e çelësave ECDHE (X25519)
  • Kërkon dhe vërteton certifikatën e klientit
  • Enkripton të dhënat e aplikacionit me AES-256-GCM

Përdorimi:
    python server.py
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


class TLSServer:
    """Server i simuluar TLS me handshake të plotë dhe komunikim të sigurt."""

    def __init__(self):
        self.logger = setup_logger("SERVER")

        if not certs_exist():
            print("[i] Certificates not found – generating now...\n")
            generate_all()

        self.server_key  = load_key("certs/server.key")
        self.server_cert = load_cert("certs/server.crt")
        self.ca_cert     = load_cert("certs/ca.crt")

        self.session_key  = None
        self.cipher_suite = None


    #  Cikli Kryesor
    
    def start(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((HOST, PORT))
            srv.listen(1)

            print(SEP2)
            print("    SSL/TLS Handshake Simulation — SERVER")
            print(SEP2)
            self.logger.info(f"Server started, listening on {HOST}:{PORT}")
            print(f"\n  [SERVER] Waiting for connections on port {PORT}...")
            print("  [SERVER] Press Ctrl+C to stop.\n")

            while True:
                try:
                    conn, addr = srv.accept()
                except KeyboardInterrupt:
                    print("\n[SERVER] Shutting down.")
                    break

                print(f"\n  [SERVER] Client connected from {addr[0]}:{addr[1]}")
                self.logger.info(f"New connection from {addr}")
                try:
                    with conn:
                        self._handle_client(conn)
                except Exception as exc:
                    self.logger.error(f"Session error: {exc}")
                    print(f"\n  [SERVER] ✗ Session error: {exc}")

    
    #  Sesioni i Klientit
    
    def _handle_client(self, conn: socket.socket) -> None:
        self._perform_handshake(conn)
        self._secure_communication(conn)

    
    #  TLS Handshake (11 Hapa)
    
    def _perform_handshake(self, conn: socket.socket) -> None:
        self.logger.info("=== SSL/TLS Handshake Initiated ===")
        print(f"\n  {SEP}")
        print("   HANDSHAKE PHASE")
        print(f"  {SEP}")

        # ── Hapi 1: Prano ClientHello ────────────────────────────────────
        msg = recv_message(conn)
        self._assert_type(msg, CLIENT_HELLO)
        ch = msg["payload"]
        client_random      = b64_decode(ch["random"])
        offered_suites     = ch["cipher_suites"]
        client_tls_version = ch["tls_version"]

        self.logger.info(f"[Step 1] ClientHello | version={client_tls_version} | suites={offered_suites}")
        print(f"\n  [←] Step  1/11 · ClientHello received")
        print(f"       TLS Version   : {client_tls_version}")
        print(f"       Cipher Suites : {', '.join(offered_suites)}")

        # ── Hapi 2: Dërgo ServerHello ────────────────────────────────────
        server_random = os.urandom(32)
        self.cipher_suite = CIPHER_SUITES[0]   # zgjidh suite-n më të mirë të mbështetur
        session_id = b64_encode(os.urandom(16))

        send_message(conn, SERVER_HELLO, {
            "tls_version": TLS_VERSION,
            "random": b64_encode(server_random),
            "session_id": session_id,
            "cipher_suite": self.cipher_suite,
            "compression_method": "null",
        })
        self.logger.info(f"[Step 2] ServerHello sent | cipher={self.cipher_suite}")
        print(f"\n  [→] Step  2/11 · ServerHello sent")
        print(f"       Selected Suite : {self.cipher_suite}")
        print(f"       Session ID     : {session_id[:20]}...")

        # ── Hapi 3: Dërgo Certifikatën ───────────────────────────────────
        cert_pem    = self.server_cert.public_bytes(serialization.Encoding.PEM).decode()
        ca_cert_pem = self.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        cn = self.server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        send_message(conn, CERTIFICATE, {
            "certificate":    cert_pem,
            "ca_certificate": ca_cert_pem,
            "subject":        str(self.server_cert.subject),
            "issuer":         str(self.server_cert.issuer),
            "valid_from":     cert_not_before(self.server_cert).isoformat(),
            "valid_until":    cert_not_after(self.server_cert).isoformat(),
            "serial_number":  str(self.server_cert.serial_number),
        })
        self.logger.info(f"[Step 3] Certificate sent | CN={cn}")
        print(f"\n  [→] Step  3/11 · Certificate sent")
        issuer_cn = self.server_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        print(f"       Subject      : {cn}")
        print(f"       Issued by    : {issuer_cn}")
        print(f"       Valid until  : {cert_not_after(self.server_cert).strftime('%Y-%m-%d')}")

        # ── Hapi 4: ServerKeyExchange (ECDHE-X25519) ─────────────────────
        srv_ecdh_priv  = X25519PrivateKey.generate()
        srv_ecdh_pub   = srv_ecdh_priv.public_key()
        srv_ecdh_bytes = srv_ecdh_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        # Nënshkruaj (server_random ‖ client_random ‖ server_ecdh_pub) me çelësin RSA
        sign_data = server_random + client_random + srv_ecdh_bytes
        signature = self.server_key.sign(sign_data, padding.PKCS1v15(), hashes.SHA256())

        send_message(conn, SERVER_KEY_EXCHANGE, {
            "key_exchange_algorithm": "ECDHE-X25519",
            "ecdh_public_key": b64_encode(srv_ecdh_bytes),
            "signature":        b64_encode(signature),
            "signature_algorithm": "RSA-PKCS1v15-SHA256",
        })
        self.logger.info("[Step 4] ServerKeyExchange sent (ECDHE-X25519)")
        print(f"\n  [→] Step  4/11 · ServerKeyExchange sent  (ECDHE-X25519)")
        print(f"       Server DH Pub  : {b64_encode(srv_ecdh_bytes)[:32]}...")
        print(f"       Signature Alg  : RSA-PKCS1v15-SHA256")

        # ── Hapi 5: CertificateRequest ───────────────────────────────────
        issuer_dn = str(self.ca_cert.subject)
        send_message(conn, CERTIFICATE_REQUEST, {
            "certificate_types":    ["RSA", "ECDSA"],
            "signature_algorithms": ["SHA256+RSA", "SHA384+RSA"],
            "certificate_authorities": [issuer_dn],
        })
        self.logger.info("[Step 5] CertificateRequest sent")
        print(f"\n  [→] Step  5/11 · CertificateRequest sent")
        print(f"       Acceptable CA  : {issuer_dn[:50]}...")

        # ── Hapi 6: ServerHelloDone ──────────────────────────────────────
        send_message(conn, SERVER_HELLO_DONE, {})
        self.logger.info("[Step 6] ServerHelloDone sent")
        print(f"\n  [→] Step  6/11 · ServerHelloDone sent")

        # ── Hapi 7: Prano ClientCertificate ──────────────────────────────
        msg = recv_message(conn)
        self._assert_type(msg, CLIENT_CERTIFICATE)
        client_cert_pem = msg["payload"].get("certificate", "")

        if client_cert_pem:
            client_cert = load_pem_x509_certificate(client_cert_pem.encode())
            cli_cn = client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            self.logger.info(f"[Step 7] Client certificate received | CN={cli_cn}")
            print(f"\n  [←] Step  7/11 · Client Certificate received")
            print(f"       Subject      : {cli_cn}")
            # Verifiko që certifikata e klientit është nënshkruar nga CA jonë
            self._verify_cert_by_ca(client_cert)
            print(f"       ✓ Client cert verified against trusted CA")
        else:
            self.logger.info("[Step 7] Client sent empty certificate")
            print(f"\n  [←] Step  7/11 · Client Certificate (none provided)")
            client_cert = None

        # ── Hapi 8: Prano ClientKeyExchange ──────────────────────────────
        msg = recv_message(conn)
        self._assert_type(msg, CLIENT_KEY_EXCHANGE)
        cli_ecdh_bytes = b64_decode(msg["payload"]["ecdh_public_key"])

        # Llogarit sekretin e përbashkët ECDHE
        cli_ecdh_pub = X25519PublicKey.from_public_bytes(cli_ecdh_bytes)
        shared_secret = srv_ecdh_priv.exchange(cli_ecdh_pub)

        # Nxirr çelësin simetrik të sesionit përmes HKDF-SHA256
        self.session_key = self._derive_session_key(
            shared_secret, client_random, server_random
        )

        self.logger.info("[Step 8] ClientKeyExchange received | shared secret derived")
        print(f"\n  [←] Step  8/11 · ClientKeyExchange received")
        print(f"       Client DH Pub  : {b64_encode(cli_ecdh_bytes)[:32]}...")
        print(f"       ✓ Shared secret computed via ECDHE")
        print(f"       ✓ Session key derived via HKDF-SHA256")

        # ── Hapi 9: Prano CertificateVerify ──────────────────────────────
        msg = recv_message(conn)
        self._assert_type(msg, CERTIFICATE_VERIFY)
        cv_ok = False
        if client_cert is not None:
            try:
                cv_sig  = b64_decode(msg["payload"]["signature"])
                cv_data = b64_decode(msg["payload"]["signed_data"])
                client_cert.public_key().verify(
                    cv_sig, cv_data, padding.PKCS1v15(), hashes.SHA256()
                )
                cv_ok = True
                self.logger.info("[Step 9] CertificateVerify: signature valid")
            except Exception as exc:
                self.logger.warning(f"[Step 9] CertificateVerify failed: {exc}")

        print(f"\n  [←] Step  9/11 · CertificateVerify received")
        if client_cert:
            icon = "✓" if cv_ok else "✗"
            status = "valid" if cv_ok else "INVALID"
            print(f"       {icon} Handshake signature {status}")

        # ── Hapi 10a: Prano ChangeCipherSpec ─────────────────────────────
        msg = recv_message(conn)
        self._assert_type(msg, CHANGE_CIPHER_SPEC)
        self.logger.info("[Step 10a] ChangeCipherSpec received from client")
        print(f"\n  [←] Step 10/11 · ChangeCipherSpec  (Client → Server)")

        # ── Hapi 10b: Prano Finished ─────────────────────────────────────
        msg = recv_message(conn)
        self._assert_type(msg, FINISHED)
        cli_verify = b64_decode(msg["payload"]["verify_data"])
        self.logger.info("[Step 10b] Client Finished received")
        print(f"  [←]          · Finished received  | verify={b64_encode(cli_verify)[:20]}...")

        # ── Hapi 11a: Dërgo ChangeCipherSpec ─────────────────────────────
        send_message(conn, CHANGE_CIPHER_SPEC, {"message": "1"})
        self.logger.info("[Step 11a] ChangeCipherSpec sent")
        print(f"\n  [→] Step 11/11 · ChangeCipherSpec  (Server → Client)")

        # ── Hapi 11b: Dërgo Finished ─────────────────────────────────────
        srv_verify = hashlib.sha256(self.session_key + b"server finished").digest()
        send_message(conn, FINISHED, {"verify_data": b64_encode(srv_verify)})
        self.logger.info("[Step 11b] Server Finished sent")
        print(f"  [→]          · Finished sent       | verify={b64_encode(srv_verify)[:20]}...")

        # ── Handshake i Përfunduar ───────────────────────────────────────
        self.logger.info("=== Handshake Complete – Secure channel established ===")
        print(f"\n  {SEP}")
        print("   ✓ SSL/TLS HANDSHAKE COMPLETE")
        print("   ✓ Secure Communication Channel Established")
        print(f"   ✓ Cipher Suite : {self.cipher_suite}")
        print(f"   ✓ Session Key  : {b64_encode(self.session_key)[:24]}...")
        print(f"  {SEP}")


    #  Shkëmbimi i të Dhënave të Aplikacionit i Enkriptuar
    
    def _secure_communication(self, conn: socket.socket) -> None:
        print(f"\n  {SEP}")
        print("   SECURE APPLICATION DATA PHASE  (AES-256-GCM)")
        print(f"  {SEP}")

        aesgcm = AESGCM(self.session_key)

        # Prano mesazhin e enkriptuar nga klienti
        msg = recv_message(conn)
        if msg["type"] != APPLICATION_DATA:
            return

        nonce      = b64_decode(msg["payload"]["nonce"])
        ciphertext = b64_decode(msg["payload"]["ciphertext"])
        plaintext  = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

        self.logger.info(f"[APP] Decrypted client message: {plaintext!r}")
        print(f"\n  [←] Encrypted message received")
        print(f"       Nonce      : {b64_encode(nonce)[:20]}...")
        print(f"       Ciphertext : {b64_encode(ciphertext)[:36]}...")
        print(f"       Decrypted  : \"{plaintext}\"")

        # Dërgo përgjigjen e enkriptuar
        ts  = datetime.datetime.utcnow().strftime("%H:%M:%S UTC")
        response = (
            f"Message received! Server says hello at {ts}. "
            "Your data arrived encrypted and intact."
        )
        nonce2      = os.urandom(12)
        ciphertext2 = aesgcm.encrypt(nonce2, response.encode(), None)

        send_message(conn, APPLICATION_DATA, {
            "nonce":      b64_encode(nonce2),
            "ciphertext": b64_encode(ciphertext2),
        })
        self.logger.info(f"[APP] Sent encrypted response: {response!r}")
        print(f"\n  [→] Encrypted response sent")
        print(f"       Plaintext  : \"{response}\"")

        print(f"\n  {SEP2}")
        print("  Session complete. Connection closed.")
        print(f"  {SEP2}\n")

    #  Ndihmës Kriptografikë
    def _verify_cert_by_ca(self, cert) -> None:
        """Ngre ValueError nëse certifikata nuk është nënshkruar nga CA e besuar."""
        try:
            self.ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            self.logger.info("Client certificate: verified against trusted CA")
        except Exception as exc:
            self.logger.error(f"Client certificate invalid: {exc}")
            raise ValueError(f"Client certificate not signed by trusted CA: {exc}")

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


# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    server = TLSServer()
    server.start()
