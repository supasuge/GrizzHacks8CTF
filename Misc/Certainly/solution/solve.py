#!/usr/bin/python3
from __future__ import annotations
import argparse
import base64
import socket
import ssl
from urllib.parse import urlparse
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID, ObjectIdentifier


FLAG_OID = ObjectIdentifier("1.3.6.1.4.1.1337.42.1")


def fetch_leaf_cert_pem(host: str, port: int) -> bytes:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der, backend=default_backend())
    return cert.public_bytes(encoding=ssl.PEM_cert_to_DER_cert.__globals__['ssl'].Encoding.PEM)  # type: ignore


def load_cert_from_pem(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem, backend=default_backend())


def load_cert_from_der(der: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(der, backend=default_backend())


def extract_aia_ca_issuers_url(cert: x509.Certificate) -> str:
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    for desc in aia:
        if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            return desc.access_location.value
    raise ValueError("No CA Issuers URL found in AIA.")


def extract_flag_from_intermediate(intermediate: x509.Certificate) -> str:
    ext = intermediate.extensions.get_extension_for_oid(FLAG_OID).value
    raw: bytes = ext.value  # UnrecognizedExtension exposes bytes
    if not raw.startswith(b"BH-CTF:"):
        raise ValueError("Unexpected flag extension format.")
    b64 = raw.split(b":", 1)[1]
    return base64.b64decode(b64).decode("utf-8", errors="strict")


def main() -> int:
    ap = argparse.ArgumentParser(description="Solve the PKI AIA chain CTF challenge")
    ap.add_argument("--host", required=True, help="Target hostname (e.g., challenge.example.com)")
    ap.add_argument("--tls-port", type=int, default=443, help="TLS port (default 443)")
    ap.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds (default 10)")
    args = ap.parse_args()

    # 1) Pull leaf cert from TLS
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((args.host, args.tls_port), timeout=args.timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=args.host) as ssock:
            leaf_der = ssock.getpeercert(binary_form=True)

    leaf = load_cert_from_der(leaf_der)

    # 2) Find AIA CA Issuers URL
    aia_url = extract_aia_ca_issuers_url(leaf)
    print(f"[+] AIA CA Issuers URL: {aia_url}")

    # 3) Download intermediate
    # If hostname in AIA differs from args.host (common in real life), still follow it.
    r = requests.get(aia_url, timeout=args.timeout)
    r.raise_for_status()
    intermediate_der = r.content
    intermediate = load_cert_from_der(intermediate_der)
    print("[+] Downloaded intermediate certificate (DER).")

    # 4) Extract custom extension flag
    flag = extract_flag_from_intermediate(intermediate)
    print(f"[+] FLAG: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())