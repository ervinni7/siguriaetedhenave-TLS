# Simulimi i SSL/TLS Handshake

Ky projekt simulon mënyrën se si funksionon komunikimi i sigurt mes një klienti dhe një serveri përmes protokollit SSL/TLS.

Projekti është ndërtuar në Python dhe demonstron hapat kryesorë të TLS handshake, duke përfshirë gjenerimin e certifikatave, verifikimin e tyre, shkëmbimin e çelësave dhe dërgimin e mesazheve të enkriptuara.

---

## Çfarë bën projekti?

- Gjeneron certifikata për CA, serverin dhe klientin.
- Starton një server TLS lokal.
- Starton një klient që lidhet me serverin.
- Simulon procesin SSL/TLS handshake.
- Verifikon certifikatën e serverit.
- Krijon një session key të përbashkët mes klientit dhe serverit.
- Enkripton dhe dekripton mesazhet me AES-GCM.
- Shfaq në terminal secilin hap të komunikimit.

---

## Teknologjitë e përdorura

- Python
- Cryptography library
- RSA për certifikata dhe nënshkrime digjitale
- X.509 për certifikata
- ECDHE-X25519 për shkëmbimin e çelësave
- HKDF-SHA256 për krijimin e session key
- AES-256-GCM për enkriptimin e të dhënave

---

## Struktura e projektit

```text
tls_simulation/
├── generate_certs.py    # Gjeneron certifikatat
├── tls_common.py        # Funksione të përbashkëta
├── server.py            # Serveri TLS
├── client.py            # Klienti TLS
├── run_simulation.py    # Ekzekuton demonstrimin automatikisht
└── README.md