import { Buffer } from 'buffer';

import ipCodec from '@leichtgewicht/ip-codec';

import { CryptoPAn } from '../cryptopan';
import { TEST_SETS } from './test_data';


describe(`matches the test/example cases of existing implementations`, () => {

  describe.each(TEST_SETS)('TEST_SETS[$#]', ({ KEY, IPV4, IPV6 }) => {

    const cryptopan = new CryptoPAn(KEY);

    if (IPV4) {
      test(`IPv4 addresses`, () => {
        expect.hasAssertions();
        for (const [original, expected] of IPV4) {
          const originalBytes = ipCodec.v4.encode(original);
          const result = cryptopan.pseudonymiseIPv4(originalBytes);
          const resultString = ipCodec.v4.decode(result);

          expect(resultString).toBe(expected);
        }
      });
    }

    if (IPV6) {
      test(`IPv6 addresses`, () => {
        expect.hasAssertions();
        for (const [original, expected] of IPV6) {
          const originalBytes = ipCodec.v6.encode(original);
          const result = cryptopan.pseudonymiseIPv6(originalBytes);
          const resultString = ipCodec.v6.decode(result);

          expect(resultString).toBe(expected);
        }
      });
    }
  });
});


describe(`de-pseudonymises correctly`, () => {

  describe.each(TEST_SETS)('TEST_SETS[$#]', ({ KEY, IPV4, IPV6 }) => {

    const cryptopan = new CryptoPAn(KEY);

    if (IPV4) {
      test(`IPv4 addresses`, () => {
        expect.hasAssertions();
        for (const [original, pseudonymised] of IPV4) {
          const pseudonymisedBytes = ipCodec.v4.encode(pseudonymised);
          const result = cryptopan.depseudonymiseIPv4(pseudonymisedBytes);
          const resultString = ipCodec.v4.decode(result);

          expect(resultString).toBe(original);
        }
      });
    }

    if (IPV6) {
      test(`IPv6 addresses`, () => {
        expect.hasAssertions();
        for (const [original, pseudonymised] of IPV6) {
          const pseudonymisedBytes = ipCodec.v6.encode(pseudonymised);
          const result = cryptopan.depseudonymiseIPv6(pseudonymisedBytes);
          const resultString = ipCodec.v6.decode(result);

          try {
            expect(resultString).toBe(original);
          } catch {
            // Sometimes the original address may not be in the
            // abbreviated/normalized form that ipCodec outputs
            const normalizedOriginal = ipCodec.v6.decode(ipCodec.v6.encode(original));
            expect(resultString).toBe(normalizedOriginal);
          }
        }
      });
    }
  });
});


describe(`new CryptoPAn()`, () => {

  test(`throws on unsupported key types`, () => {
    // @ts-expect-error
    expect(() => new CryptoPAn()).toThrow(TypeError);

    const BAD_KEYS = [
      '32-char-str-for-AES-key-and-pad.',
      0x33322d636861722d7374722d666f722d4145532d6b65792d616e642d7061642e,
      0x33322d636861722d7374722d666f722d4145532d6b65792d616e642d7061642en,
    ];
    for (const key of BAD_KEYS) {
      // @ts-expect-error
      expect(() => new CryptoPAn(key)).toThrow(TypeError);
    }
  });

  test(`throws on wrong key buffer length`, () => {
    for (const length of [0, 1, 31, 33]) {
      expect(() => new CryptoPAn(Buffer.alloc(length))).toThrow(RangeError);
    }
  });
});


const BAD_IPV4_INPUT = [
  '192.0.2.1',
  [192,0,2,1],
  0xc0000201,
  0xc0000201n,
];
const BAD_IPV6_INPUT = [
  '2001:0db8::0001',
  [0x20,0x01,0x0d,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01],
  0x20010db8000000000000000000000001,
  0x20010db8000000000000000000000001n,
];

const cryptopan = new CryptoPAn(Buffer.alloc(32));


describe(`pseudonymiseIP()`, () => {

  test(`throws on unsupported input types`, () => {
    for (const input of [...BAD_IPV4_INPUT, ...BAD_IPV6_INPUT]) {
      // @ts-expect-error
      expect(() => cryptopan.pseudonymiseIP(input)).toThrow(TypeError);
    }
  });
});


describe(`depseudonymiseIP()`, () => {

  test(`throws on unsupported input types`, () => {
    for (const input of [...BAD_IPV4_INPUT, ...BAD_IPV6_INPUT]) {
      // @ts-expect-error
      expect(() => cryptopan.depseudonymiseIP(input)).toThrow(TypeError);
    }
  });
});


describe(`pseudonymiseIPv4()`, () => {

  test(`throws on unsupported input types`, () => {
    for (const input of BAD_IPV4_INPUT) {
      // @ts-expect-error
      expect(() => cryptopan.pseudonymiseIPv4(input)).toThrow(TypeError);
    }
  });

  test(`throws on IPv6 length input buffer`, () => {
    expect(() => cryptopan.pseudonymiseIPv4(Buffer.alloc(16))).toThrow(RangeError);
  });
});


describe(`depseudonymiseIPv4()`, () => {

  test(`throws on unsupported input types`, () => {
    for (const input of BAD_IPV4_INPUT) {
      // @ts-expect-error
      expect(() => cryptopan.depseudonymiseIPv4(input)).toThrow(TypeError);
    }
  });

  test(`throws on IPv6 length input buffer`, () => {
    expect(() => cryptopan.depseudonymiseIPv4(Buffer.alloc(16))).toThrow(RangeError);
  });
});


describe(`pseudonymiseIPv6()`, () => {

  test(`throws on unsupported input types`, () => {
    for (const input of BAD_IPV6_INPUT) {
      // @ts-expect-error
      expect(() => cryptopan.pseudonymiseIPv6(input)).toThrow(TypeError);
    }
  });

  test(`throws on IPv4 length input buffer`, () => {
    expect(() => cryptopan.pseudonymiseIPv6(Buffer.alloc(4))).toThrow(RangeError);
  });
});


describe(`depseudonymiseIPv6()`, () => {

  test(`throws on unsupported input types`, () => {
    for (const input of BAD_IPV6_INPUT) {
      // @ts-expect-error
      expect(() => cryptopan.depseudonymiseIPv6(input)).toThrow(TypeError);
    }
  });

  test(`throws on IPv4 length input buffer`, () => {
    expect(() => cryptopan.depseudonymiseIPv6(Buffer.alloc(4))).toThrow(RangeError);
  });
});


describe(`_pseudonymise()`, () => {

  test(`throws when input buffer length is more than 16 bytes (128 bits)`, () => {
    expect(() => cryptopan['_pseudonymise'](Buffer.alloc(17))).toThrow(RangeError);
  });

  test(`output length is the same as input length`, () => {
    for (const length of [0, 1, 4, 10, 15, 16]) {
      const output = cryptopan['_pseudonymise'](Buffer.alloc(length));
      expect(output).toHaveLength(length);
    }
  });

  test(`output is an instance of Buffer when input is an instance of Buffer`, () => {
    const pseudonymisedBuffer = cryptopan['_pseudonymise'](Buffer.alloc(4));
    expect(pseudonymisedBuffer).toBeInstanceOf(Buffer);
  });

  test(`output is an instance of Uint8Array when input is an instance of Uint8Array`, () => {
    const pseudonymisedUint8Array = cryptopan['_pseudonymise'](new Uint8Array(4));
    expect(pseudonymisedUint8Array).toBeInstanceOf(Uint8Array);
    // Buffer is a subclass of Uint8Array:
    expect(pseudonymisedUint8Array).not.toBeInstanceOf(Buffer);
    // Just in case there are any Jest shenanigans:
    expect(Buffer.prototype).toBeInstanceOf(Uint8Array);
    expect(pseudonymisedUint8Array).toHaveLength(4);
  });
});


describe(`_decrypt()`, () => {

  test(`throws when input buffer length is more than 16 bytes (128 bits)`, () => {
    expect(() => cryptopan['_decrypt'](Buffer.alloc(17))).toThrow(RangeError);
  });

  test(`output length is the same as input length`, () => {
    for (const length of [0, 1, 4, 10, 15, 16]) {
      const output = cryptopan['_decrypt'](Buffer.alloc(length));
      expect(output).toHaveLength(length);
    }
  });

  test(`output is an instance of Buffer when input is an instance of Buffer`, () => {
    const pseudonymisedBuffer = cryptopan['_decrypt'](Buffer.alloc(4));
    expect(pseudonymisedBuffer).toBeInstanceOf(Buffer);
  });

  test(`output is an instance of Uint8Array when input is an instance of Uint8Array`, () => {
    const pseudonymisedUint8Array = cryptopan['_decrypt'](new Uint8Array(4));
    expect(pseudonymisedUint8Array).toBeInstanceOf(Uint8Array);
    // Buffer is a subclass of Uint8Array:
    expect(pseudonymisedUint8Array).not.toBeInstanceOf(Buffer);
    // Just in case there are any Jest shenanigans:
    expect(Buffer.prototype).toBeInstanceOf(Uint8Array);
    expect(pseudonymisedUint8Array).toHaveLength(4);
  });
});
