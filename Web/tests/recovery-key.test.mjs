import assert from 'node:assert/strict';
import {test} from 'node:test';
import {deriveP256KeyPair} from '../recovery-key.js';

test('P-256 recovery derivation matches RFC 9180 A.3.1, including the public point', async() => {
  // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.3.1
  const material = Buffer.from('4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e', 'hex');
  const pair = await deriveP256KeyPair(material);
  const privateKey = await crypto.subtle.exportKey('jwk', pair.privateKey);
  assert.equal(Buffer.from(privateKey.d, 'base64url').toString('hex'),
    '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb');
  const publicKey = Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey));
  assert.equal(publicKey.toString('hex'),
    '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4');
});
