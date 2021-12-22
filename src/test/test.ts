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

console.log(`Tests completed successfully!`);
