import {ed25519} from '@noble/curves/ed25519.js';

const bytes = value => new Uint8Array(value);
const prefix = new Uint8Array([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32]);

export async function importIdentity(raw) {
  const secret = bytes(raw), pkcs8 = new Uint8Array(48);
  try {
    if(secret.length !== 32) throw new Error('Invalid Ed25519 secret');
    pkcs8.set(prefix); pkcs8.set(secret, 16);
    return await crypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', false, ['sign']);
  } finally { secret.fill(0); pkcs8.fill(0); }
}

export async function identityPublicKey(secret) {
  let hashed, scalar = 0n;
  try {
    hashed = new Uint8Array(await crypto.subtle.digest('SHA-512', secret));
    hashed[0] &= 248; hashed[31] = (hashed[31] & 63) | 64;
    for(let i = 31; i >= 0; i--) scalar = (scalar << 8n) | BigInt(hashed[i]);
    return ed25519.Point.BASE.multiply(scalar % ed25519.Point.Fn.ORDER).toBytes();
  } finally { hashed?.fill(0); scalar = 0n; }
}

export async function verify(key, message, signature) {
  const algorithm = key.length === 32 ? 'Ed25519' : {name: 'ECDSA', namedCurve: 'P-256'};
  const publicKey = await crypto.subtle.importKey('raw', bytes(key), algorithm, false, ['verify']);
  return crypto.subtle.verify(key.length === 32 ? 'Ed25519' : {name: 'ECDSA', hash: 'SHA-256'},
    publicKey, bytes(signature), bytes(message));
}

export function requireDevice(device) {
  const key = device?.privateKey;
  if(key?.type !== 'private' || key.extractable !== false || key.algorithm?.name !== 'ECDSA' ||
    key.algorithm.namedCurve !== 'P-256' || !key.usages.includes('sign') ||
    !(device.publicKey instanceof Uint8Array) || device.publicKey.length !== 65 || device.publicKey[0] !== 4) {
    throw new TypeError('Invalid non-extractable P-256 device');
  }
  return device;
}

export const deviceKeys = {
  async generate() {
    const pair = await crypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, false, ['sign']);
    return {privateKey: pair.privateKey, publicKey: bytes(await crypto.subtle.exportKey('raw', pair.publicKey))};
  }
};

export function signingBackend(identity, device) {
  requireDevice(device);
  return {
    random: count => crypto.getRandomValues(new Uint8Array(count)),
    publicKey: role => role === 'identity' ? identity.publicKey.slice(-32) : device.publicKey,
    sign: async(role, message) => bytes(await crypto.subtle.sign(
      role === 'identity' ? 'Ed25519' : {name: 'ECDSA', hash: 'SHA-256'},
      role === 'identity' ? identity.signer : device.privateKey, bytes(message))),
    verify
  };
}

