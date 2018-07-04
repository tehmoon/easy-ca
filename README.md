## Easy-CA

Easy-CA is a quick and easy CA handler for x509 certificates.

It's meant to be a drop in replacement of `easy-rsa` with a lot of exciting features along the way!

![output.gif](https://github.com/tehmoon/img/raw/master/easy-ca/output.gif)

Or through flags:

```
password=blih ./easy-ca -p ./pki -e password export --name ca
```

## Usage

```
Usage:
  easy-ca [flags]
  easy-ca [command]

Available Commands:
  create      
  create-ca   
  crl         
  export      
  help        Help about any command
  init        
  revoke      

Flags:
  -e, --env-password string   Environment variable for password
  -h, --help                  help for easy-ca
  -p, --path string           Path to the easy-ca directory database

Use "easy-ca [command] --help" for more information about a command.
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

  - Time validity for certificates and CRL
  - Copy path flag to config
  - List certificates
  - Add x509 v3 Alternative Names constrains from parsing the common name
  - Auto CRL at create/revoke
  - Set command: (path)
  - Req server
  - Generate cert + keys send to server
