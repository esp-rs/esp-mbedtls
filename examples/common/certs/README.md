# Certificates for the `esp-mbedtls` Examples

This folder contains certificates used by the examples:
- `ca-bundle.pem`
  - This is a certificate bundle (a sequence of PEM certificates) containing all ROOT CAs of the Mozilla browser
  - The bundle was obtained by running cURL's [`mk-ca-bundle.pl` Perls script](https://curl.se/docs/mk-ca-bundle.html) as follows:
    ```sh
    mk-ca-bundle.pl ca-bundle.pem
    ```
- `ca-bundle-small.pem`
  - A manual extraction of just two root CAs from `ca-bundle.pem` which are known to be used by the websites used in the client examples (`httpbin.org` and `certauth.cryptomix.com`)
  - Done for reducing memory and flash size when using `esp-mbedtls`
- `cert.der` / `cert.pem` + `key.der` / `key.pem`
  - Self-signed certificate used by the server examples and its corresponding key
  - Can be re-generated with:
    ```sh
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=esp-mbedtls.local"
    openssl x509 -in cert.pem -out cert.der -outform DER
    openssl rsa -in key.pem -out key.der -outform DER
    ```
