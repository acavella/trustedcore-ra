# Trusted Core: RA
A custom registration authority client to be used with the ISC CertAgent RAMI API, which allows for the automated generation of single or bulk x.509 certificates. This script assumes the user has some familiarity with manual operation of ISC CertAgent, is familiar with the RAMI API and its client certificates and trustchains.

## Prerequisites

### Client
- Bash
- OpenSSL
- Curl

### Certificate Authority / Server
- ISC CertAgent 7.0.9.x
- RAMI API Configured 

## References

- ISC CertAgent 7.0.9.x Installation Guide
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)

## Installation
This script requires no `root` privileges and is designed to be run from the user's home directory. 

1. Clone latest from Github:
```shell
$ cd ~
$ git clone https://github.com/acavella/trustedcore-ra.git
```
2. Copy ca trust and client (RAMI) certificates to your home directory:
```shell
$ cp ca-root.pem ~
$ cp rami-client.pfx ~
```
3. Using OpenSSL, convert the client PKCS12 certificate to PEM format:
```shell
$ openssl pkcs12 -in <p12 file> -out ~/trustedcore-ra-main/cert/client.pem -nodes
```
4. Using OpenSSL, convert the trustchain from DER to PEM format (if trustchain is already PEM this can be skipped):
```shell
$ openssl x509 –inform der –in <root cert> -out ~/trustedcore-ra-main/cert/ca-trust.pem
```

## Usage
This script is meant to be operated directly from CLI; all options are specified inline. The first operator is an input file which consists of a lists of Common Names (CN) to be used in the generation of PKCS#10 Certificate Signing Requests (CSR). The second operator is certificate specification (ECDSA, ECDH, RSA), which are based on specifications in CNSSP 15 (Use of Public Standards for Secure Information Sharing).

### ECDSA Generation
```shell
$ ./tcra.sh <input-file> ecdsa
```

### ECDH Generation
```shell
$ ./tcra.sh <input-file> ecdh
```

### RSA Generation
```shell
$ ./tcra.sh <input-file> rsa
```

## License & Credits

### Author

**Tony Cavella** 
- <tony@cavella.com>
- <https://github.com/acavella/trustedcore-ra>

### License

MIT License

Copyright (c) 2022 Tony Cavella

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.