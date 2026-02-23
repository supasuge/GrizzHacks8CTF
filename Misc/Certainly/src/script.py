#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID, AuthorityInformationAccessOID, ObjectIdentifier


FLAG_OID = ObjectIdentifier("1.3.6.1.4.1.1337.42.1")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def gen_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def pem_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def der_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def build_name(common_name: str, org: str, ou: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Michigan"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Detroit"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def make_root_ca() -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = gen_rsa_key()
    subject = issuer = build_name("BinaryHive Root CA", "Binary Hive", "CTF PKI Root")

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(utcnow() - timedelta(days=1))
        .not_valid_after(utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )

    cert = builder.sign(private_key=key, algorithm=hashes.SHA256())
    return key, cert


def make_intermediate_ca(
    root_key: rsa.RSAPrivateKey,
    root_cert: x509.Certificate,
    flag: str,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = gen_rsa_key()
    subject = build_name("BinaryHive Intermediate CA", "Binary Hive", "CTF PKI Intermediate")
    issuer = root_cert.subject

    # Put the flag in a custom extension.
    # Keep it non-obvious: base64 payload with a prefix.
    payload_b64 = base64.b64encode(flag.encode("utf-8"))
    ext_value = b"BH-CTF:" + payload_b64  # bytes inside the extension

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(utcnow() - timedelta(days=1))
        .not_valid_after(utcnow() + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .add_extension(x509.UnrecognizedExtension(FLAG_OID, ext_value), critical=False)
    )

    cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256())
    return key, cert


def make_leaf_cert(
    int_key: rsa.RSAPrivateKey,
    int_cert: x509.Certificate,
    hostname: str,
    aia_http_url: str,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = gen_rsa_key()
    subject = build_name(hostname, "Binary Hive", "CTF Leaf Service")
    issuer = int_cert.subject

    san = x509.SubjectAlternativeName([x509.DNSName(hostname)])

    # AIA points to intermediate DER over HTTP (common in real PKI)
    aia = x509.AuthorityInformationAccess(
        [
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(aia_http_url),
            )
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(utcnow() - timedelta(days=1))
        .not_valid_after(utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(san, critical=False)
        .add_extension(aia, critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,   # TLS RSA key exchange (simplified; still fine for CTF)
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(int_key.public_key()),
            critical=False,
        )
    )

    cert = builder.sign(private_key=int_key, algorithm=hashes.SHA256())
    return key, cert


def write_file(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if mode is not None:
        os.chmod(path, mode)


def render_nginx_conf(template_path: Path, out_path: Path, leaf_cert: Path, leaf_key: Path) -> None:
    tmpl = template_path.read_text(encoding="utf-8")
    rendered = (
        tmpl.replace("{{LEAF_CERT}}", str(leaf_cert))
            .replace("{{LEAF_KEY}}", str(leaf_key))
    )
    out_path.write_text(rendered, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate PKI chain for CTF challenge")
    ap.add_argument("--out-dir", required=True, help="Directory to write keys/certs/nginx.conf")
    ap.add_argument("--web-dir", required=True, help="Web root directory (for AIA-served intermediate)")
    ap.add_argument("--hostname", required=True, help="Hostname used in leaf cert SAN/CN and AIA URL host")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    web_dir = Path(args.web_dir)
    hostname = args.hostname

    # The AIA URL embedded in the leaf cert; served over HTTP by nginx on port 80.
    aia_url = f"http://{hostname}/.well-known/pki/intermediate.der"

    # Generate a per-container flag by default.
    # If you want static flags, replace this with a constant or ENV var.
    flag = f"GRIZZ{{pki_aia_chain_{secrets.token_hex(12)}}}"

    root_key, root_cert = make_root_ca()
    int_key, int_cert = make_intermediate_ca(root_key, root_cert, flag)
    leaf_key, leaf_cert = make_leaf_cert(int_key, int_cert, hostname, aia_url)

    # Output locations
    root_pem = out_dir / "root_ca.pem"
    int_pem = out_dir / "intermediate_ca.pem"
    int_der = web_dir / ".well-known" / "pki" / "intermediate.der"
    leaf_pem = out_dir / "leaf.pem"
    leaf_key_pem = out_dir / "leaf.key"

    # Write artifacts
    write_file(root_pem, pem_cert(root_cert))
    write_file(out_dir / "root_ca.key", pem_key(root_key), mode=0o600)

    write_file(int_pem, pem_cert(int_cert))
    write_file(out_dir / "intermediate_ca.key", pem_key(int_key), mode=0o600)

    write_file(int_der, der_cert(int_cert))

    write_file(leaf_pem, pem_cert(leaf_cert))
    write_file(leaf_key_pem, pem_key(leaf_key), mode=0o600)

    # Render nginx config
    template = Path("/app/nginx.conf.template")
    nginx_conf = out_dir / "nginx.conf"
    render_nginx_conf(template, nginx_conf, leaf_pem, leaf_key_pem)

    # Also drop a tiny “admin” note for you (not exposed) to verify flag quickly
    write_file(out_dir / "FLAG_ADMIN_NOTE.txt", flag.encode("utf-8"))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())