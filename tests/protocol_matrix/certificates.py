#!/usr/bin/env python3
"""Generate the short-lived protocol-matrix CA, server key, and secret."""

import argparse
import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def write_private(path, key):
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ankah protocol test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                                       key_cert_sign=True, key_agreement=False,
                                       content_commitment=False, data_encipherment=False,
                                       crl_sign=True, encipher_only=None, decipher_only=None),
                         critical=True)
          .sign(ca_key, hashes.SHA256()))

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "native.ankah.test")])
    leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca_name)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.DNSName("edge.ankah.test"),
                x509.DNSName("native.ankah.test")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True,
                                         key_cert_sign=False, key_agreement=False,
                                         content_commitment=False, data_encipherment=False,
                                         crl_sign=False, encipher_only=None, decipher_only=None),
                           critical=True)
            .sign(ca_key, hashes.SHA256()))

    write_private(args.output / "ca-key.pem", ca_key)
    write_private(args.output / "leaf-key.pem", leaf_key)
    (args.output / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (args.output / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (args.output / "secret").write_text(os.urandom(32).hex(), encoding="ascii")
    (args.output / "secret").chmod(0o600)


if __name__ == "__main__":
    main()
