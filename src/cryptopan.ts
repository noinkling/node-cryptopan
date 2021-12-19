import crypto from 'crypto';
import { Buffer } from 'buffer';


export class CryptoPan {
  #cipher;
  #padding;

  constructor(key: Buffer) {
    if (!(key instanceof Buffer)) {
      throw new TypeError('`key` must be a Buffer object');
    }
    if (key.length !== 32) {
      throw new RangeError('`key` length must be 32 bytes (256 bits)');
    }

    // Use copies in case the memory for the original `key` changes:
    const cipherKey = Uint8Array.prototype.slice.call(key, 0, 16);
    const padding = Uint8Array.prototype.slice.call(key, 16, 32);

    this.#cipher = crypto.createCipheriv('aes-128-ecb', cipherKey, null);
    // We use our own padding scheme:
    this.#cipher.setAutoPadding(false);

    this.#padding = this.#cipher.update(padding);
  }

  pseudonymise(ip: Buffer) {
    if (!(ip instanceof Buffer)) {
      throw new TypeError('`ip` must be a Buffer object');
    }
    if (ip.length !== 4) {
      throw new RangeError('`ip` length must be 4 bytes (32 bits)');
    }

    // Creates a copy:
    const input = Buffer.from(this.#padding);
    // One-time pad, 32-bit buffer initialised with 0s:
    const otp = Buffer.alloc(4, 0);

    let output = this.#cipher.update(input);
    let byteIndex = 0;
    let bitIndex = 0;
    otp[byteIndex] |= (output[0] >>> 7) << 7;

    for (let i = 0; i < 31; ) {  // i is incremented inside the loop

      const paddingMask = 0xff >>> (bitIndex + 1);
      const ipMask = ~paddingMask;

      const ipByte = ip[byteIndex];
      const paddingByte = this.#padding[byteIndex];

      input[byteIndex] = (ipByte & ipMask) | (paddingByte & paddingMask);

      output = this.#cipher.update(input);

      // Makes things easier to increment here:
      i++;
      byteIndex = i >>> 3;  // like Math.trunc(i / 8)
      bitIndex = i & 7;  // like i % 8

      otp[byteIndex] |= (output[0] >>> 7) << (7 - bitIndex);
    }

    return ip.map((ipByte, byteIndex) => ipByte ^ otp[byteIndex]);
  }
}
