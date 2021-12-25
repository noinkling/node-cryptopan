// TODO: Use a proper test runner/framework
import assert from 'assert/strict';
import ipCodec from '@leichtgewicht/ip-codec'

import { CryptoPAn } from '../cryptopan';
import { TEST_SETS } from './test_data';


for (const testData of TEST_SETS) {
  const cryptopan = new CryptoPAn(testData.KEY);

  if (testData.IPV4) {
    for (const [original, pseudonymised] of testData.IPV4) {
      const originalBytes = ipCodec.v4.encode(original);
      const result = cryptopan.pseudonymiseIPv4(originalBytes);
      const resultString = ipCodec.v4.decode(result);

      assert.equal(resultString, pseudonymised);
    }
  }

  if (testData.IPV6) {
    for (const [original, pseudonymised] of testData.IPV6) {
      const originalBytes = ipCodec.v6.encode(original);
      const result = cryptopan.pseudonymiseIPv6(originalBytes);
      const resultString = ipCodec.v6.decode(result);

      assert.equal(resultString, pseudonymised);
    }
  }
}

console.log(`Output tests completed.`);

// Sanity tests
{
  // @ts-expect-error
  assert.throws(() => new CryptoPAn(), TypeError);
  // @ts-expect-error
  assert.throws(() => new CryptoPAn('32-char-str-for-AES-key-and-pad.'), TypeError);
  // @ts-expect-error
  assert.throws(() => new CryptoPAn(0x33322d636861722d7374722d666f722d4145532d6b65792d616e642d7061642e), TypeError);

  for (const length of [0, 1, 31, 33]) {
    assert.throws(() => new CryptoPAn(Buffer.alloc(length)), RangeError);
  }

  const cryptopan = new CryptoPAn(Buffer.alloc(32));

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

  for (const input of [...BAD_IPV4_INPUT, ...BAD_IPV6_INPUT]) {
    // @ts-expect-error
    assert.throws(() => cryptopan.pseudonymiseIP(input), TypeError);
  }

  for (const input of BAD_IPV4_INPUT) {
    // @ts-expect-error
    assert.throws(() => cryptopan.pseudonymiseIPv4(input), TypeError);
  }
  assert.throws(() => cryptopan.pseudonymiseIPv4(Buffer.alloc(16)), RangeError);

  for (const input of BAD_IPV6_INPUT) {
    // @ts-expect-error
    assert.throws(() => cryptopan.pseudonymiseIPv6(input), TypeError);
  }
  assert.throws(() => cryptopan.pseudonymiseIPv6(Buffer.alloc(4)), RangeError);

  for (const length of [0, 1, 4, 10, 15, 16]) {
    const outputLength = cryptopan['_pseudonymise'](Buffer.alloc(length)).length;
    assert.equal(outputLength, length);
  }
  assert.throws(() => cryptopan['_pseudonymise'](Buffer.alloc(17)), RangeError);

  const pseudonymisedBuffer = cryptopan['_pseudonymise'](Buffer.alloc(4));
  assert(pseudonymisedBuffer instanceof Buffer);

  const pseudonymisedUint8Array = cryptopan['_pseudonymise'](new Uint8Array(4));
  assert(pseudonymisedUint8Array instanceof Uint8Array);
  assert(!(pseudonymisedUint8Array instanceof Buffer));
  assert.equal(pseudonymisedUint8Array.length, 4);

  console.log(`Sanity tests completed.`);
}

console.log(`All tests completed successfully!`);
