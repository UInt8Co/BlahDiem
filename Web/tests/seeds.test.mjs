import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {test} from 'node:test';
import {identityContext, seeds} from '../seeds.js';

const api = seeds();
const hex = value => Buffer.from(value).toString('hex');
const vectors = JSON.parse(await readFile(new URL('../.build-embedded/checkouts/diem/Tests/Vectors/identity-seed.json', import.meta.url)));

test('JS codec, context and identity match representative committed Diem vectors', async() => {
  for(const index of [0, 3, 4]) {
    const vector = vectors.vectors[index], entropy = Buffer.from(vector.entropy, 'hex');
    try {
      assert.equal(hex(identityContext), vector.context['1']);
      assert.equal(api.words(entropy).join(' '), vector.phrase);
      const restored = api.restore(` \t${vector.phrase.toUpperCase().replaceAll(' ', '\n')}\r\v\f`);
      try { assert.equal(hex(restored), vector.entropy); } finally { restored.fill(0); }
      const identity = await api.identity(entropy);
      assert.equal(hex(identity.publicKey), vector.identityKey['1']);
      assert.equal(identity.signer.extractable, false);
      const message = new Uint8Array([1, 2, 3]);
      const publicKey = await crypto.subtle.importKey('raw', identity.publicKey.slice(-32), 'Ed25519', false, ['verify']);
      assert.equal(await crypto.subtle.verify('Ed25519', publicKey,
        await crypto.subtle.sign('Ed25519', identity.signer, message), message), true);
    } finally { entropy.fill(0); }
  }
  for(const phrase of vectors.invalid) assert.throws(() => api.restore(phrase));
  const phrase = vectors.vectors[0].phrase;
  const padded = api.restore(' '.repeat(1025) + phrase);
  try { assert.equal(hex(padded), vectors.vectors[0].entropy); } finally { padded.fill(0); }
  assert.throws(() => api.restore(phrase.replace(' ', '\u00a0')));
  for(const entropy of [new Uint8Array(31), Array(32).fill(-1), new Array(32)]) {
    assert.throws(() => api.words(entropy));
    await assert.rejects(() => api.identity(entropy));
  }
});

test('identity temporaries are cleared after success, mismatch and WebCrypto failures', async() => {
  const subtle = crypto.subtle;
  const original = Object.fromEntries(['importKey', 'deriveBits', 'digest'].map(name => [name, subtle[name]]));
  const entropy = new Uint8Array(32).fill(123);
  try {
    for(const failure of [undefined, 'mismatch', 'HKDF', 'deriveBits', 'digest', 'Ed25519']) {
      const buffers = [];
      subtle.importKey = async function(format, input, algorithm, extractable, usages) {
        buffers.push(input);
        assert.equal(extractable, false);
        if(algorithm === failure) throw new Error('injected');
        return original.importKey.call(this, format, input, algorithm, extractable, usages);
      };
      subtle.deriveBits = async function(algorithm, key, length) {
        assert.equal(key.extractable, false);
        assert.deepEqual(key.usages, ['deriveBits']);
        if(failure === 'deriveBits') throw new Error('injected');
        const result = await original.deriveBits.call(this, algorithm, key, length);
        buffers.push(new Uint8Array(result));
        return result;
      };
      subtle.digest = async function(algorithm, input) {
        if(failure === 'digest') throw new Error('injected');
        const result = await original.digest.call(this, algorithm, input);
        buffers.push(new Uint8Array(result));
        return result;
      };
      if(failure) await assert.rejects(() => api.identity(entropy, failure === 'mismatch' ? [] : undefined));
      else await api.identity(entropy);
      assert.ok(buffers.length > 0);
      for(const buffer of buffers) assert.ok(buffer.every(byte => byte === 0), `${failure}: retained secret`);
      assert.ok(entropy.every(byte => byte === 123), 'caller retains ownership');
    }
  } finally { Object.assign(subtle, original); entropy.fill(0); }
});

test('generation clears unreturned entropy when randomness fails', () => {
  const random = crypto.getRandomValues;
  let input;
  crypto.getRandomValues = bytes => { input = bytes; bytes.fill(123); throw new Error('injected'); };
  try {
    assert.throws(() => api.generate());
    assert.ok(input.every(byte => byte === 0));
  } finally { crypto.getRandomValues = random; }
});
