import {HkdfSha256} from '@hpke/core';
import {p256} from '@noble/curves/nist.js';

const utf8 = text => new TextEncoder().encode(text);
const base64url = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const kdf = new HkdfSha256();
kdf.init(new Uint8Array([0x4b, 0x45, 0x4d, 0, 0x10])); // "KEM" || DHKEM(P-256, HKDF-SHA256)

// RFC 9180 §7.1.3, with complete JWK imports. @hpke/core's DeriveKeyPair
// imports scalar-only PKCS#8, which Cocoa WebKit rejects because it requires
// the public point. Keep the exact scalar and point (including y's sign) so
// existing files and native clients derive the same HPKE recipient.
export async function deriveP256KeyPair(material) {
  const prk = new Uint8Array(await kdf.labeledExtract(new Uint8Array(), utf8('dkp_prk'), material));
  try {
    for(let counter = 0; counter <= 255; counter++) {
      const secret = new Uint8Array(await kdf.labeledExpand(prk, utf8('candidate'), new Uint8Array([counter]), 32));
      try {
        if(!p256.utils.isValidSecretKey(secret)) continue;
        const point = p256.getPublicKey(secret, false);
        const jwk = {kty: 'EC', crv: 'P-256', x: base64url(point.subarray(1, 33)), y: base64url(point.subarray(33))};
        const algorithm = {name: 'ECDH', namedCurve: 'P-256'};
        const privateKey = await crypto.subtle.importKey('jwk', {...jwk, d: base64url(secret)}, algorithm, true, ['deriveBits']);
        const publicKey = await crypto.subtle.importKey('jwk', jwk, algorithm, true, []);
        return {privateKey, publicKey};
      } finally { secret.fill(0); }
    }
    throw new Error('Unable to derive the P-256 recovery key');
  } finally { prk.fill(0); }
}
