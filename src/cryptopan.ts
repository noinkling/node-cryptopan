import crypto from 'crypto';
import { Buffer } from 'buffer';

import {
  assertIsUint8Array,
  assertLength,
  assertBufferIsIPv4Length,
  assertBufferIsIPv6Length,
  assertBufferIsIPv4Or6Length,
} from './utils';


const MSB_OF_BYTE_MASK = 0b1000_0000;


export class CryptoPAn {

  readonly #cipher;
  readonly #padding: Buffer;

  /**
   * @param key - A 32-byte (256-bit) buffer used to derive the cipher key and padding
   */
  constructor(key: Buffer | Uint8Array) {
    assertIsUint8Array(key, `'key' must be a Buffer or Uint8Array`);
    assertLength(key, 32, `'key' buffer must be 32 bytes (256 bits) in length`);

    // Use copies in case the memory for the original `key` changes:
    const cipherKey = Uint8Array.prototype.slice.call(key, 0, 16);
    const paddingInput = Uint8Array.prototype.slice.call(key, 16, 32);

    this.#cipher = crypto.createCipheriv('aes-128-ecb', cipherKey, null);
    // CryptoPAn uses its own padding scheme:
    this.#cipher.setAutoPadding(false);

    this.#padding = this.#cipher.update(paddingInput);
  }

  /**
   * Pseudonymise an IPv4 or IPv6 address
   * @param ip - A 4-byte or 16-byte buffer representing an IP address
   */
  pseudonymiseIP(ip: Buffer | Uint8Array) {
    assertIsUint8Array(ip, `IP address must be provided as a Buffer or Uint8Array`);
    assertBufferIsIPv4Or6Length(ip,
      `Provided IP address buffer must be 4 bytes (32 bits) in length for IPv4, or 16 bytes (128 bits) for IPv6, was ${ip.length} bytes`
    );
    return this._pseudonymise(ip);
  }

  /**
   * Pseudonymise an IPv4 address
   * @param ip - A 4-byte buffer representing an IPv4 address
   */
  pseudonymiseIPv4(ip: Buffer | Uint8Array) {
    assertIsUint8Array(ip, `IP address must be provided as a Buffer or Uint8Array`);
    assertBufferIsIPv4Length(ip,
      `Provided IPv4 address buffer must be 4 bytes (32 bits) in length, was ${ip.length} bytes`
    );
    return this._pseudonymise(ip);
  }

  /**
   * Pseudonymise an IPv6 address
   * @param ip - A 16-byte buffer representing an IPv6 address
   */
  pseudonymiseIPv6(ip: Buffer | Uint8Array) {
    assertIsUint8Array(ip, `IP address must be provided as a Buffer or Uint8Array`);
    assertBufferIsIPv6Length(ip,
      `Provided IPv6 address buffer must be 16 bytes (128 bits) in length, was ${ip.length} bytes`
    );
    return this._pseudonymise(ip);
  }

  /**
   * De-pseudonymise an IPv4 or IPv6 address
   * @param pseudonymisedIP - A 4-byte or 16-byte buffer representing a pseudonymised IP address
   */
  depseudonymiseIP(pseudonymisedIP: Buffer | Uint8Array) {
    assertIsUint8Array(pseudonymisedIP,
      `Pseudonymised IP address must be provided as a Buffer or Uint8Array`
    );
    assertBufferIsIPv4Or6Length(pseudonymisedIP,
      `Provided buffer must be 4 bytes (32 bits) in length for a pseudonymised IPv4 address, or 16 bytes (128 bits) for a pseudonymised IPv6 address, was ${pseudonymisedIP.length} bytes`
    );
    return this._decrypt(pseudonymisedIP);
  }

  /**
   * De-pseudonymise an IPv4 address
   * @param pseudonymisedIP - A 4-byte buffer representing a pseudonymised IPv4 address
   */
  depseudonymiseIPv4(pseudonymisedIP: Buffer | Uint8Array) {
    assertIsUint8Array(pseudonymisedIP,
      `Pseudonymised IP address must be provided as a Buffer or Uint8Array`
    );
    assertBufferIsIPv4Length(pseudonymisedIP,
      `Provided pseudonymised IPv4 address buffer must be 4 bytes (32 bits) in length, was ${pseudonymisedIP.length} bytes`
    );
    return this._decrypt(pseudonymisedIP);
  }

  /**
   * De-pseudonymise an IPv6 address
   * @param pseudonymisedIP - A 16-byte buffer representing a pseudonymised IPv6 address
   */
  depseudonymiseIPv6(pseudonymisedIP: Buffer | Uint8Array) {
    assertIsUint8Array(pseudonymisedIP,
      `Pseudonymised IP address must be provided as a Buffer or Uint8Array`
    );
    assertBufferIsIPv6Length(pseudonymisedIP,
      `Provided pseudonymised IPv6 address buffer must be 16 bytes (128 bits) in length, was ${pseudonymisedIP.length} bytes`
    );
    return this._decrypt(pseudonymisedIP);
  }

  /**
   * Pseudonymise a byte sequence
   */
  protected _pseudonymise(original: Buffer | Uint8Array) {
    assertIsUint8Array(original, `Provided argument must be a Buffer or Uint8Array`);
    if (original.length > 16 || original.length < 0) {
      throw new RangeError(
        `Provided buffer must be between 0 and 16 bytes (128 bits) in length, was ${original.length} bytes`
      );
    }
    // Creates a copy:
    const cipherInput = Buffer.from(this.#padding);
    // One-time pad, initialised with 0s, which will be XORed later:
    const otp = Buffer.alloc(original.length, 0);

    let cipherOutput = this.#cipher.update(cipherInput);
    let byteIndex = 0;
    let bitIndex = 0;
    otp[byteIndex] |= cipherOutput[0] & MSB_OF_BYTE_MASK;

    const iterations = original.length * 8 - 1;
    for (let i = 0; i < iterations; ) {  // i is incremented inside the loop body
      const paddingMask = 0xff >>> (bitIndex + 1);
      const originalMask = ~paddingMask;

      const originalByte = original[byteIndex];
      const paddingByte = this.#padding[byteIndex];

      cipherInput[byteIndex] = (originalByte & originalMask) | (paddingByte & paddingMask);

      cipherOutput = this.#cipher.update(cipherInput);

      // Makes things easier to increment here:
      i++;
      byteIndex = i >>> 3;  // like Math.trunc(i / 8)
      bitIndex = i & 7;  // like i % 8

      otp[byteIndex] |= (cipherOutput[0] & MSB_OF_BYTE_MASK) >>> bitIndex;
    }

    return original.map(
      (originalByte, i) => originalByte ^ otp[i]
    // TS doesn't know that calling .map on a Buffer returns a Buffer:
    ) as typeof original;
  }

  /**
   * De-pseudonymise a byte sequence
   */
  protected _decrypt(pseudonymised: Buffer | Uint8Array) {
    assertIsUint8Array(pseudonymised, `Provided argument must be a Buffer or Uint8Array`);
    if (pseudonymised.length > 16 || pseudonymised.length < 0) {
      throw new RangeError(
        `Provided buffer must be between 0 and 16 bytes (128 bits) in length, was ${pseudonymised.length} bytes`
      );
    }

    const cipherInput = Buffer.from(this.#padding);
    // Will be transformed in-place to the original/decrypted sequence:
    const result = Uint8Array.prototype.slice.call(pseudonymised);

    let cipherOutput = this.#cipher.update(cipherInput);
    let byteIndex = 0;
    let bitIndex = 0;
    result[byteIndex] ^= cipherOutput[0] & MSB_OF_BYTE_MASK;

    const iterations = pseudonymised.length * 8 - 1;
    for (let i = 0; i < iterations; ) {
      const paddingMask = 0xff >>> (bitIndex + 1);
      const originalMask = ~paddingMask;

      const originalByteSoFar = result[byteIndex] & originalMask;
      const paddingByte = this.#padding[byteIndex];

      cipherInput[byteIndex] = originalByteSoFar | (paddingByte & paddingMask);

      cipherOutput = this.#cipher.update(cipherInput);

      i++;
      byteIndex = i >>> 3;
      bitIndex = i & 7;

      const toXOR = (cipherOutput[0] & MSB_OF_BYTE_MASK) >>> bitIndex;
      result[byteIndex] ^= toXOR;
    }

    return result;
  }
}

export default CryptoPAn;
