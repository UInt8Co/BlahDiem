import {encode} from './cbor.js';

// Independent integer-keyed InvocationChallenge fixture.
export default encode({
  0: 4, 1: 1, 2: 'alice.example.org', 3: new Uint8Array(32).fill(7),
  4: 1800000060, 5: new Uint8Array(32).fill(42),
  6: 18446744073709551614n, 7: 18446744073709551613n
});
