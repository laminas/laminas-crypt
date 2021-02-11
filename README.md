# laminas-crypt

[![Build Status](https://github.com/laminas/laminas-crypt/workflows/Continuous%20Integration/badge.svg)](https://github.com/laminas/laminas-crypt/actions?query=workflow%3A"Continuous+Integration")

`Laminas\Crypt` provides support of some cryptographic tools.
Some of the available features are:

- encrypt-then-authenticate using symmetric ciphers (the authentication step
  is provided using HMAC);
- encrypt/decrypt using symmetric and public key algorithm (e.g. RSA algorithm);
- encrypt/decrypt using hybrid mode (OpenPGP like);
- generate digital sign using public key algorithm (e.g. RSA algorithm);
- key exchange using the Diffie-Hellman method;
- key derivation function (e.g. using PBKDF2 algorithm);
- secure password hash (e.g. using Bcrypt algorithm);
- generate Hash values;
- generate HMAC values;

The main scope of this component is to offer an easy and secure way to protect
and authenticate sensitive data in PHP.

- File issues at https://github.com/laminas/laminas-crypt/issues
- Documentation is at https://docs.laminas.dev/laminas-crypt
