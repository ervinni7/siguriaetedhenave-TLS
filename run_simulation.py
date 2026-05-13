"""
run_simulation.py - Ekzekutuesi i plotë i demonstrimit

E ekzekuton simulimin e plotë të SSL/TLS handshake në një terminal të vetëm:
  1. Gjeneron certifikatat nëse nuk ekzistojnë
  2. Nis TLS serverin në një thread në prapavijë
  3. Pret derisa serveri të jetë gati
  4. Ekzekuton TLS klientin në thread-in kryesor

Përdorimi:
    python run_simulation.py
"""

import sys
import time
import socket
import threading

# ─────────────────────────────────────────────────────────────
#  Hapi 0: Gjenerimi i certifikatave
# ─────────────────────────────────────────────────────────────
from generate_certs import generate_all, certs_exist

SEP = "═" * 60

def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Kontrollon derisa serveri të fillojë të pranojë lidhje."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _run_server() -> None:
    from server import TLSServer
    srv = TLSServer()
    srv.start()


def main() -> None:
    print(SEP)
    print("  SSL/TLS Handshake Simulation — FULL DEMO")
    print(SEP)

    # 1. Certifikatat
    if not certs_exist():
        print("\n[*] Certificates not found – generating PKI...\n")
        generate_all()
    else:
        print("\n[✓] Certificates found in certs/ directory.")

    # 2. Nis serverin në një thread të veçantë
    # daemon=True bën që serveri të mbyllet kur përfundon programi kryesor
    print("\n[*] Starting server thread...")
    srv_thread = threading.Thread(target=_run_server, daemon=True)
    srv_thread.start()

    # 3. Pret derisa serveri të jetë gati për lidhje
    if not _wait_for_port("127.0.0.1", 8443, timeout=6.0):
        print("[✗] Server did not start in time. Exiting.")
        sys.exit(1)

    print("[✓] Server is ready.\n")
    time.sleep(0.3)   # pauzë e shkurtër për dalje më të pastër në terminal

    # 4. Ekzekuton klientin
    from client import TLSClient
    cli = TLSClient()
    cli.connect()

    print("\n[*] Demo finished. Press Enter to exit.")
    try:
        input()
    except EOFError:
        pass


if __name__ == "__main__":
    main()