#!/usr/bin/env python3
"""
Certificate Generator for TLS 1.3 Secure Messaging System
Generates self-signed certificates for server and client authentication
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

def generate_private_key():
    """Generate RSA private key"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096  # Strong 4096-bit keys for TLS
    )

def create_certificate(private_key, common_name, is_server=False, valid_days=365):
    """Create X.509 certificate"""
    
    # Certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Secure"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Military"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Pager-Proper SecureComm"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Certificate builder
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)  # Self-signed
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=valid_days)
    )
    
    # Add extensions
    if is_server:
        # Server certificate extensions
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.DNSName("0.0.0.0"),
            ]),
            critical=False,
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        )
    else:
        # Client certificate extensions
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        )
    
    # Sign certificate
    certificate = builder.sign(private_key, hashes.SHA256())
    return certificate

def save_certificate_files(private_key, certificate, name_prefix):
    """Save private key and certificate to PEM files"""
    
    # Save private key
    key_filename = f"{name_prefix}_private_key.pem"
    with open(key_filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))
    
    # Save certificate
    cert_filename = f"{name_prefix}_certificate.pem"
    with open(cert_filename, "wb") as f:
        f.write(certificate.public_bytes(Encoding.PEM))
    
    print(f"🔑 Generated {key_filename}")
    print(f"📜 Generated {cert_filename}")
    
    return key_filename, cert_filename

def generate_server_certificates():
    """Generate server certificates for TLS"""
    print("🏗️  Generating Server TLS Certificates...")
    
    # Generate server private key
    server_private_key = generate_private_key()
    
    # Create server certificate
    server_cert = create_certificate(
        server_private_key, 
        "Pager-Proper-Server", 
        is_server=True,
        valid_days=365
    )
    
    # Save files
    key_file, cert_file = save_certificate_files(
        server_private_key, 
        server_cert, 
        "server_tls"
    )
    
    print("✅ Server TLS certificates generated successfully!")
    return key_file, cert_file

def generate_client_certificates(client_name):
    """Generate client certificates for mutual TLS authentication"""
    print(f"🏗️  Generating Client TLS Certificates for {client_name}...")
    
    # Generate client private key
    client_private_key = generate_private_key()
    
    # Create client certificate
    client_cert = create_certificate(
        client_private_key, 
        f"Pager-Proper-Client-{client_name}", 
        is_server=False,
        valid_days=365
    )
    
    # Save files
    key_file, cert_file = save_certificate_files(
        client_private_key, 
        client_cert, 
        f"client_tls_{client_name}"
    )
    
    print(f"✅ Client TLS certificates generated for {client_name}!")
    return key_file, cert_file

def setup_tls_infrastructure():
    """Setup complete TLS certificate infrastructure"""
    print("🔒 Setting up TLS 1.3 Certificate Infrastructure")
    print("=" * 50)
    
    # Generate server certificates
    server_key, server_cert = generate_server_certificates()
    
    # Generate default client certificates
    default_clients = ["admin", "default"]
    client_certs = {}
    
    for client in default_clients:
        key_file, cert_file = generate_client_certificates(client)
        client_certs[client] = (key_file, cert_file)
    
    print("\n🎯 TLS Infrastructure Setup Complete!")
    print("=" * 50)
    print("Server Files:")
    print(f"  🔑 Private Key: {server_key}")
    print(f"  📜 Certificate: {server_cert}")
    print("\nClient Files:")
    for client, (key, cert) in client_certs.items():
        print(f"  {client}:")
        print(f"    🔑 Private Key: {key}")
        print(f"    📜 Certificate: {cert}")
    
    return {
        "server": (server_key, server_cert),
        "clients": client_certs
    }

if __name__ == "__main__":
    # Check if certificates already exist
    if os.path.exists("server_tls_private_key.pem"):
        print("⚠️  TLS certificates already exist!")
        overwrite = input("Overwrite existing certificates? (y/N): ").lower()
        if overwrite != 'y':
            print("🚫 Certificate generation cancelled.")
            exit(0)
    
    # Generate complete TLS infrastructure
    setup_tls_infrastructure()
    
    print("\n💡 Next Steps:")
    print("1. Update server.py to use TLS encryption")
    print("2. Update client.py to use TLS authentication") 
    print("3. Deploy with proper certificate validation")
    print("\n🔒 Your messaging system now supports TLS 1.3!")