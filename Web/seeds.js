import {sha256} from '@noble/hashes/sha2.js';
import {identityPublicKey, importIdentity} from './crypto-support.js';
import {seedWords} from './seed-words.js';

// Canonical CBOR {0:"Diem/identity-seed", 1:1, 2:1, 3:1} (Ed25519).
export const identityContext = new Uint8Array([
  0xa4, 0, 0x72, 0x44, 0x69, 0x65, 0x6d, 0x2f, 0x69, 0x64, 0x65, 0x6e, 0x74,
  0x69, 0x74, 0x79, 0x2d, 0x73, 0x65, 0x65, 0x64, 1, 1, 2, 1, 3, 1
]);
const keyPrefix = new Uint8Array([
  0xa5, 0, 0x68, 0x44, 0x69, 0x65, 0x6d, 0x2f, 0x6b, 0x65, 0x79, 1, 3, 2, 1, 3, 1, 4, 0x58, 0x20
]);
const indices = new Map(seedWords.map((word, index) => [word, index]));

function requireEntropy(value) {
  if(!(value instanceof Uint8Array || Array.isArray(value)) || value.length !== 32) {
    throw new TypeError('Invalid identity seed');
  }
  for(const byte of value) {
    if(!Number.isInteger(byte) || byte < 0 || byte > 255) throw new TypeError('Invalid identity seed');
  }
}

function words(entropy) {
  requireEntropy(entropy);
  const input = new Uint8Array(entropy);
  let checksum, accumulator = 0, bits = 0;
  try {
    checksum = sha256(input);
    const result = [];
    for(let i = 0; i < 33; i++) {
      accumulator = (accumulator << 8) | (i === 32 ? checksum[0] : input[i]);
      bits += 8;
      if(bits >= 11) {
        bits -= 11;
        result.push(seedWords[accumulator >>> bits]);
        accumulator &= (1 << bits) - 1;
      }
    }
    return result;
  } finally { input.fill(0); checksum?.fill(0); accumulator = bits = 0; }
}

function restore(phrase) {
  if(typeof phrase !== 'string') throw new TypeError('Invalid recovery words');
  const decoded = new Uint8Array(33);
  const entropy = decoded.subarray(0, 32);
  let checksum, word = '', count = 0, accumulator = 0, bits = 0, offset = 0;
  const consume = () => {
    if(word === '') return;
    const index = indices.get(word);
    word = '';
    if(++count > 24 || index === undefined) throw new Error('invalidEncoding');
    accumulator = (accumulator << 11) | index;
    bits += 11;
    while(bits >= 8) { bits -= 8; decoded[offset++] = accumulator >>> bits; }
    accumulator &= (1 << bits) - 1;
  };
  try {
    // Consume ASCII words directly, without copying the whole recovery phrase.
    for(let i = 0; i < phrase.length; i++) {
      const code = phrase.charCodeAt(i);
      if(code === 0x20 || (code >= 0x09 && code <= 0x0d)) consume();
      else word += code >= 0x41 && code <= 0x5a ? String.fromCharCode(code | 0x20) : phrase[i];
    }
    consume();
    if(count !== 24) throw new Error('invalidEncoding');
    checksum = sha256(entropy);
    if(checksum[0] !== decoded[32]) throw new Error('invalidEncoding');
    return entropy.slice();
  } finally { decoded.fill(0); checksum?.fill(0); word = phrase = ''; accumulator = bits = 0; }
}

export function seeds() {
  return {
    generate() {
      const entropy = new Uint8Array(32);
      let returned = false;
      try {
        crypto.getRandomValues(entropy);
        const result = {words: words(entropy), entropy};
        returned = true;
        return result;
      } finally { if(!returned) entropy.fill(0); }
    },
    restore,
    words,
    async identity(entropy, expected) {
      requireEntropy(entropy);
      const input = new Uint8Array(entropy);
      let baseKey, secret;
      try {
        baseKey = await crypto.subtle.importKey('raw', input, 'HKDF', false, ['deriveBits']);
        secret = new Uint8Array(await crypto.subtle.deriveBits({name: 'HKDF', hash: 'SHA-256',
          salt: new Uint8Array(), info: identityContext}, baseKey, 256));
        const raw = await identityPublicKey(secret);
        const publicKey = new Uint8Array(keyPrefix.length + raw.length);
        publicKey.set(keyPrefix); publicKey.set(raw, keyPrefix.length);
        if(expected != null && (!(expected instanceof Uint8Array || Array.isArray(expected)) ||
          expected.length !== publicKey.length || !publicKey.every((byte, index) => byte === expected[index]))) {
          throw new Error('identityMismatch');
        }
        const id = Array.from(sha256(publicKey), byte => byte.toString(16).padStart(2, '0')).join('');
        return {publicKey, id, signer: await importIdentity(secret)};
      } finally { input.fill(0); secret?.fill(0); baseKey = undefined; }
    }
  };
}
