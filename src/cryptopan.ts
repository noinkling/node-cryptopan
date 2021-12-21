import crypto from 'crypto';
import { Buffer } from 'buffer';


export class CryptoPan {
  readonly #cipher;
  readonly #padding;

  constructor(key: Buffer | Uint8Array) {
    if (!(key instanceof Buffer)) {
      throw new TypeError(`'key' must be a Buffer or Uint8Array`);
    }
    if (key.length !== 32) {
      throw new RangeError(`'key' buffer must be 32 bytes (256 bits) in length`);
    }

    // Use copies in case the memory for the original `key` changes:
    const cipherKey = Uint8Array.prototype.slice.call(key, 0, 16);
    const padding = Uint8Array.prototype.slice.call(key, 16, 32);

    this.#cipher = crypto.createCipheriv('aes-128-ecb', cipherKey, null);
    // We use our own padding scheme:
    this.#cipher.setAutoPadding(false);

    this.#padding = this.#cipher.update(padding);
  }

  pseudonymise(ip: Buffer | Uint8Array) {
    if (!(ip instanceof Uint8Array)) {
      throw new TypeError(`Provided IP address must be a Buffer or Uint8Array`);
    }
    if (ip.length !== 4 && ip.length !== 16) {
      throw new RangeError(
        `Provided IP address buffer must be 4 bytes (32 bits) in length for IPv4, or 16 bytes (128 bits) for IPv6, was ${ip.length} bytes`
      );
    }

    return this._pseudonymise(ip);
  }

  pseudonymiseIPv4(ip: Buffer | Uint8Array) {
    if (!(ip instanceof Uint8Array)) {
      throw new TypeError(`Provided IP address must be a Buffer or Uint8Array`);
    }
    if (ip.length !== 4) {
      throw new RangeError(
        `Provided IP address buffer must be 4 bytes (32 bits) in length, was ${ip.length} bytes`
      );
    }

    return this._pseudonymise(ip);
  }

  pseudonymiseIPv6(ip: Buffer | Uint8Array): never {
    if (!(ip instanceof Uint8Array)) {
      throw new TypeError(`Provided IP address must be a Buffer or Uint8Array`);
    }
    if (ip.length !== 16) {
      throw new RangeError(
        `Provided IP address buffer must be 16 bytes (128 bits) in length, was ${ip.length} bytes`
      );
    }

    throw new Error('Not implemented')
  }

  _pseudonymise(ip: Buffer | Uint8Array) {
    // Creates a copy:
    const cipherInput = Buffer.from(this.#padding);
    // One-time pad, 32-bit buffer initialised with 0s:
    const otp = Buffer.alloc(4, 0);

    let output = this.#cipher.update(cipherInput);
    let byteIndex = 0;
    let bitIndex = 0;
    otp[byteIndex] |= (output[0] >>> 7) << 7;

    for (let i = 0; i < 31; ) {  // i is incremented inside the loop

      const paddingMask = 0xff >>> (bitIndex + 1);
      const ipMask = ~paddingMask;

      const ipByte = ip[byteIndex];
      const paddingByte = this.#padding[byteIndex];

      cipherInput[byteIndex] = (ipByte & ipMask) | (paddingByte & paddingMask);

      output = this.#cipher.update(cipherInput);

      // Makes things easier to increment here:
      i++;
      byteIndex = i >>> 3;  // like Math.trunc(i / 8)
      bitIndex = i & 7;  // like i % 8

      otp[byteIndex] |= (output[0] >>> 7) << (7 - bitIndex);
    }

    return ip.map((ipByte, byteIndex) => ipByte ^ otp[byteIndex]) as typeof ip;
  }
}
