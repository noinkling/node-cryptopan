# cryptopan

[![npm](https://img.shields.io/npm/v/cryptopan)](https://www.npmjs.com/package/cryptopan)

Node.js implementation of the [Crypto-PAn](https://en.wikipedia.org/wiki/Crypto-PAn) scheme. Cryptographically [pseudonymises](https://en.wikipedia.org/wiki/Pseudonymization) IP addresses in a way that subnets can still be compared (in addition to exact addresses).

Like the reference and most other implementations, it uses AES-128-ECB as the pseudorandom function (PRF).

## Installation

```bash
npm install cryptopan
# or
yarn add cryptopan
```

## Usage

```js
const { Buffer } = require('buffer');
const { CryptoPAn } = require('cryptopan');

const cryptopan = new CryptoPAn(SECRET_KEY);

const ipv4 = Buffer.from([192,0,2,1]);  // <Buffer c0 00 02 01>
const ipv6 = Buffer.from('20010db8000000000000000000000001', 'hex');  // <Buffer 20 01 0d b8 00 ... 01>

cryptopan.pseudonymiseIP(ipv4);  // e.g. <Buffer 3c 0c fe 2e>
cryptopan.pseudonymiseIP(ipv6);  // e.g. <Buffer a0 01 3d bc 26 30 0e 00 e2 7f 5f 84 8f 07 3e e6>
```

### Notes

In order to keep things minimal, only `Buffer` (or plain `Uint8Array`) objects are accepted as input and produced as output. If you need to convert to/from string representations of IP addresses, it's recommended to use an existing library with that capability. For example, using [ipaddr.js](https://github.com/whitequark/ipaddr.js/):

```js
const bytes = ipaddr.parse('2001:db8::1').toByteArray();  // standard array of byte values
const inputBuffer = Buffer.from(bytes);
const outputBuffer = cryptopan.pseudonymiseIP(inputBuffer);
const pseudonymisedIP = ipaddr.fromByteArray(outputBuffer).toString();
```

Outputs from different `CryptoPAn` instances are only comparable when the same secret key is used to create them. To generate an appropriate 32-byte key (which should be stored somewhere safe) you can run this from the terminal:

```bash
node -e "console.log(crypto.randomBytes(32).toString('hex'))"
```

You can use `Buffer.from(keyString, 'hex')` to convert it back to a buffer so it can be used with the `CryptoPAn` constructor.

## API

### Constructor

#### `new CryptoPAn(key)`

- `key: Buffer | Uint8Array`: 32-byte (256-bit) secret key. The first half is used as the key for the AES-128-ECB cipher. The second half is used to derive the padding.

### Pseudonymisation

The primary functionality: take an IP address and generate a pseudonym for it.

In all cases `ip` must be a `Buffer` or plain `Uint8Array`. The choice will also determine the return type.

#### `cryptopan.pseudonymiseIP(ip)`

- `ip`: Bytes representing an IPv4 or IPv6 address (network/big-endian order)

#### `cryptopan.pseudonymiseIPv4(ip)`

- `ip`: Bytes representing an IPv4 address

Throws if an IPv6 address buffer is provided.

#### `cryptopan.pseudonymiseIPv6(ip)`

- `ip`: Bytes representing an IPv6 address

Throws if an IPv4 address buffer is provided.

### De-pseudonymisation/reversal

Take an IP address pseudonym (that has been generated using the same key) and decrypt it to return the original.

In all cases `pseudonymisedIP` must be a `Buffer` or plain `Uint8Array`. The choice will also determine the return type.

#### `cryptopan.depseudonymiseIP(pseudonymisedIP)`

#### `cryptopan.depseudonymiseIPv4(pseudonymisedIP)`

#### `cryptopan.depseudonymiseIPv6(pseudonymisedIP)`

## Features that *may* be supported in the future

- Option to use a suggested technique to increase the randomness of outputs[^1]

[^1]: https://web.archive.org/web/20180908092852/https://www.cc.gatech.edu/computing/Networking/projects/cryptopan/lucent.shtml
