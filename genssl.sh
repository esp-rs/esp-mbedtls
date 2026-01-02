#!/bin/env bash
# This is a simple script to refresh the certificate chains from the links used in the example,
# and to refresh the self-signed CA and associated certificate + private key pair used for examples.

CERTS_DIR=./examples/config

# Get certificate chain for www.google.com
echo -n | openssl s_client -showcerts -connect www.google.com:443 2>/dev/null
# echo -n | openssl s_client -showcerts -connect www.google.com:443 2>/dev/null | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' > $CERTS_DIR/ca_chain_www.google.com.pem

# # Get certificate chain for certauth.cryptomix.com
# echo -n | openssl s_client -showcerts -connect certauth.cryptomix.com:443 2>/dev/null | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' > $CERTS_DIR/ca_chain_certauth.cryptomix.com.pem

# # Generate a pair of self-signed certificate + private key
# openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=esp-mbedtls.local"

# # Convert to DER format
# openssl x509 -in $CERTS_DIR/cert.pem -out $CERTS_DIR/cert.der -outform DER
# openssl rsa -in $CERTS_DIR/key.pem -out $CERTS_DIR/key.der -outform DER
