## Easy-CA

Easy-CA is a quick and easy CA handler for x509 certificates.

It's meant to be a drop in replacement of `easy-rsa` with a lot of exciting features along the way!

![output.gif](https://github.com/tehmoon/img/raw/master/easy-ca/output.gif)

Or through flags:

```
password=blih ./easy-ca -p ./pki -e password export --name ca
```

## Caveat

Not everything is implemented but the default feature set is!!

## Features

  - Raw format using protobuf for compatibility between clients
  - ~~Paranoid encryption by default to store private keys~~
  - One database file for ease of deployments
  - ~~CLI for admin bulk tasks~~
  - ~~Unix arguments flags for automated tasks~~
  - Choice between ecdsa p256 and rsa
  - Export using multiple encoding: PEM, DER
  - Export using multiple format: pkcs12, pkcs8, x509
  - ~~CRL revocation~~

## CryptoPasta

  - Use `scrypt` with `1<<20` rounds
  - 16 bits salt from go's `crypto/rand`
  - `AES` in `GCM` mode for authenticated encryption
  - 256 bits `AES` key
  - 12 bits nonce from go's `crypto/rand` for `each file` -- prepended to the encrypted data
  - `salt` + `scrypt` hash are stored in the `.pass` file which is read before doing anything
  - Derived key is stored for the CLI session in memory
  - Password is either asked from the CLI or specified in environment. NO OTHER WAY.

## TODO:

  - Export CRL
  - Export to file from CLI
