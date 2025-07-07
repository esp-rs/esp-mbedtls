#!/bin/env bash
# This is a simple script to refresh the certificate chains from the links used in the example,
# and to refresh the self-signed CA and associated certificate + private key pair used for examples.

CERTS_DIR=./examples/certs

# Get certificate chain for www.google.com
echo -n | openssl s_client -showcerts -connect www.google.com:443 2>/dev/null | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' > $CERTS_DIR/www.google.com.pem

# Get certificate chain for certauth.cryptomix.com
echo -n | openssl s_client -showcerts -connect certauth.cryptomix.com:443 2>/dev/null | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' > $CERTS_DIR/certauth.cryptomix.com.pem

# Generate a CA and a pair of certificate + private key signed with the CA

# Generate CA certificate
openssl req \
  -x509 \
  -newkey rsa:2048 \
  -keyout $CERTS_DIR/ca_key.pem \
  -out $CERTS_DIR/ca_cert.pem \
  -nodes \
  -days 365 \
  -subj "/CN=esp-mbedtls.local/O=CA\ Certificate"


# Generate certificate signing request (CSR)
openssl req \
    -newkey rsa:2048 \
    -keyout $CERTS_DIR/private_key.pem \
    -out $CERTS_DIR/csr.pem \
    -nodes \
    -subj "/CN=esp-mbedtls.local"

# Sign key with CA certificates from CSR
openssl x509 \
    -req \
    -in $CERTS_DIR/csr.pem \
    -CA $CERTS_DIR/ca_cert.pem \
    -CAkey $CERTS_DIR/ca_key.pem \
    -out $CERTS_DIR/certificate.pem \
    -CAcreateserial \
    -days 365

# Remove csr
rm $CERTS_DIR/csr.pem

# Converts to DER format
# Certificate
openssl x509 -in $CERTS_DIR/certificate.pem -out $CERTS_DIR/certificate.der -outform DER
# Private Key
openssl rsa -in $CERTS_DIR/private_key.pem -out $CERTS_DIR/private_key.der -outform DER
