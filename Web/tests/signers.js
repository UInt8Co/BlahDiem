export async function verify(key, message, signature) {
  const algorithm = key.length === 32 ? 'Ed25519' : {name: 'ECDSA', namedCurve: 'P-256'};
  const publicKey = await crypto.subtle.importKey('raw', new Uint8Array(key), algorithm, false, ['verify']);
  return crypto.subtle.verify(key.length === 32 ? 'Ed25519' : {name: 'ECDSA', hash: 'SHA-256'},
    publicKey, new Uint8Array(signature), new Uint8Array(message));
}

export function signers(identity, device) {
  return {
    random: n => crypto.getRandomValues(new Uint8Array(n)),
    publicKey: role => role === 'identity' ? identity?.publicKey.slice(-32) ?? new Uint8Array() : device.publicKey,
    sign: async(role, bytes) => new Uint8Array(await crypto.subtle.sign(
      role === 'identity' ? 'Ed25519' : {name: 'ECDSA', hash: 'SHA-256'},
      role === 'identity' ? identity.signer : device.privateKey, new Uint8Array(bytes))),
    verify
  };
}

export async function backend(diem) {
  const seed = diem.seeds.generate().entropy;
  const identity = await diem.seeds.identity(seed);
  const device = await diem.deviceKeys.generate();
  return {...signers(identity, device), seed, identity, device};
}
