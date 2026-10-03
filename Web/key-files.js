import {Aes256Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256} from '@hpke/core';

const suite = new CipherSuite({kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm()});
const pkcs8Prefix = new Uint8Array([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32]);
const encode = value => {
  const bytes = new Uint8Array(value);
  let text = '';
  for(let offset = 0; offset < bytes.length; offset += 8192) {
    text += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  return btoa(text);
};
const decode = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const bytes = value => new Uint8Array(value);

function fileBytes(value) {
  if(!(value instanceof Uint8Array || Array.isArray(value)) || value.length > 262144 ||
    !value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
    throw new Error('Invalid CBOR key file');
  }
  return Array.from(value);
}

async function restore(raw) {
  if(raw.length !== 32) throw new Error('Invalid Ed25519 secret');
  const pkcs8 = new Uint8Array(48);
  pkcs8.set(pkcs8Prefix); pkcs8.set(raw, 16);
  try { return await crypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', true, ['sign']); }
  finally { pkcs8.fill(0); }
}

async function signingKey(raw) {
  const key = await restore(raw);
  const jwk = await crypto.subtle.exportKey('jwk', key);
  const pkcs8 = bytes(await crypto.subtle.exportKey('pkcs8', key));
  try { return {privateKey: encode(pkcs8), publicKey: jwk.x.replace(/-/g, '+').replace(/_/g, '/') + '='}; }
  finally { pkcs8.fill(0); }
}

function secret(key) {
  if(!key) return null;
  const encoded = decode(key.privateKey);
  if(encoded.length !== 48 || !pkcs8Prefix.every((byte, index) => encoded[index] === byte)) {
    throw new Error('Invalid Ed25519 private key');
  }
  return Array.from(encoded.subarray(16));
}

/** Software signing-key export conventions belong to the SDK, alongside the file codec. */
export async function generateSigningKey() {
  const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const pkcs8 = bytes(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  try { return {privateKey: encode(pkcs8), publicKey: encode(await crypto.subtle.exportKey('raw', pair.publicKey))}; }
  finally { pkcs8.fill(0); }
}

export function keyFiles(exports) {
  const inspect = file => exports.keyFileInfo(fileBytes(file));
  async function create(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
    if(typeof password !== 'string' || !password.length) throw new Error('Enter an identity password.');
    salt = bytes(salt);
    if(salt.length !== 16) throw new Error('Invalid key-file salt');
    const passwordBytes = new TextEncoder().encode(password);
    let material;
    let pair;
    try {
      const key = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
      material = bytes(await crypto.subtle.deriveBits({name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600_000}, key, 256));
      pair = await suite.kem.deriveKeyPair(material);
    } finally { passwordBytes.fill(0); material?.fill(0); }
    const publicKey = bytes(await suite.kem.serializePublicKey(pair.publicKey));
    const requireKey = () => { if(!pair) throw new Error('Unlock your identity to continue.'); return pair; };
    const backend = {
      encryptionPublicKey: () => { requireKey(); return publicKey; },
      restorePublicKey: async raw => {
        const jwk = await crypto.subtle.exportKey('jwk', await restore(raw));
        return decode(jwk.x.replace(/-/g, '+').replace(/_/g, '/') + '=');
      },
      signRestored: async(raw, message) => bytes(await crypto.subtle.sign('Ed25519', await restore(raw), bytes(message))),
      verify: async(key, message, signature) => {
        const algorithm = key.length === 32 ? 'Ed25519' : {name: 'ECDSA', namedCurve: 'P-256'};
        const publicKey = await crypto.subtle.importKey('raw', bytes(key), algorithm, false, ['verify']);
        return crypto.subtle.verify(key.length === 32 ? 'Ed25519' : {name: 'ECDSA', hash: 'SHA-256'}, publicKey, bytes(signature), bytes(message));
      },
      seal: async(recipient, plaintext, context) => {
        requireKey();
        const sender = await suite.createSenderContext({recipientPublicKey: await suite.kem.deserializePublicKey(bytes(recipient)), info: bytes(context)});
        const ciphertext = await sender.seal(bytes(plaintext), bytes(context));
        return {encapsulatedKey: bytes(sender.enc), ciphertext: bytes(ciphertext)};
      },
      open: async(enc, ciphertext, context) => {
        const receiver = await suite.createRecipientContext({recipientKey: requireKey().privateKey, enc: bytes(enc), info: bytes(context)});
        return bytes(await receiver.open(bytes(ciphertext), bytes(context)));
      }
    };
    return {
      destroy() { pair = undefined; },
      async seal(value) {
        requireKey();
        const identity = secret(value.identity), device = secret(value.device);
        const policy = value.renewal || {profileDays: 180, deviceDays: 180, autoRenew: true};
        try {
          return bytes(await exports.sealKeyFile({profile: Array.from(decode(value.profile)), identity, device,
            domain: value.domain, publisher: value.publisher || '', token: value.token || '',
            profileDays: policy.profileDays, deviceDays: policy.deviceDays, autoRenew: policy.autoRenew,
            publicationPending: !!value.publicationPending}, Array.from(salt), backend));
        } finally { identity?.fill(0); device?.fill(0); }
      },
      async open(file) {
        requireKey();
        const info = inspect(file);
        if(!info.salt.every((byte, index) => salt[index] === byte)) throw new Error('Key-file salt mismatch');
        const value = await exports.openKeyFile(fileBytes(file), backend);
        try {
          return {domain: value.domain, profile: encode(value.profile),
            identity: value.identity ? await signingKey(value.identity) : undefined,
            device: value.device ? await signingKey(value.device) : undefined,
            publisher: value.publisher, token: value.token,
            renewal: {profileDays: value.profileDays, deviceDays: value.deviceDays, autoRenew: value.autoRenew},
            publicationPending: value.publicationPending};
        } finally { value.identity?.fill(0); value.device?.fill(0); }
      }
    };
  }
  return {inspect, create, async unlock(file, password) {
    const session = await create(password, inspect(file).salt);
    try { return {session, contents: await session.open(file)}; }
    catch(error) { session.destroy(); throw error; }
  }};
}
