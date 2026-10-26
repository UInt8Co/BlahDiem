import {decode} from './cbor.js';

// Fixed, public test keys at the WebCrypto boundary; production session internals stay opaque.
export async function installFixtureCrypto(vector) {
  const url = value => btoa(String.fromCharCode(...value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const point = decode(decode(vector.request)[3])[4];
  const privateKey = await crypto.subtle.importKey('jwk', {
    kty: 'EC', crv: 'P-256', x: url(point.slice(1, 33)), y: url(point.slice(33)), d: url(vector.recipientSecret)
  }, {name: 'ECDH', namedCurve: 'P-256'}, true, ['deriveBits']);
  const publicKey = await crypto.subtle.importKey('raw', point, {name: 'ECDH', namedCurve: 'P-256'}, true, []);
  const generateKey = SubtleCrypto.prototype.generateKey;
  SubtleCrypto.prototype.generateKey = function(algorithm, ...args) {
    if(algorithm.name === 'ECDH') return Promise.resolve({privateKey, publicKey});
    return generateKey.call(this, algorithm, ...args);
  };
  const getRandomValues = Crypto.prototype.getRandomValues;
  Crypto.prototype.getRandomValues = function(array) {
    if(array.byteLength === 16) { array.set(Array.from({length: 16}, (_, i) => i)); return array; }
    if(array.byteLength === 32) { array.set(vector.deviceSecret); return array; }
    return getRandomValues.call(this, array);
  };
  return () => {
    SubtleCrypto.prototype.generateKey = generateKey;
    Crypto.prototype.getRandomValues = getRandomValues;
  };
}
