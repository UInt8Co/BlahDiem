import {Aes256Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256} from '@hpke/core';
import {identityPublicKey, importIdentity, verify} from './crypto-support.js';

const suite = new CipherSuite({kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm()});
const bytes = value => new Uint8Array(value);

const seedBackend = {
  async restorePublicKey(raw) {
    const secret = bytes(raw);
    try { return await identityPublicKey(secret); }
    finally { secret.fill(0); raw.fill(0); }
  },
  async signRestored(raw, message) {
    try { return bytes(await crypto.subtle.sign('Ed25519', await importIdentity(raw), bytes(message))); }
    finally { raw.fill(0); }
  }
};

// HPKE callbacks run only in disposable link workers; Swift supplies canonical info and AAD.
export async function linkBackend(device) {
  const pair = await suite.kem.generateKeyPair();
  const publicKey = bytes(await suite.kem.serializePublicKey(pair.publicKey));
  return {
    ...seedBackend,
    random: count => crypto.getRandomValues(new Uint8Array(count)),
    publicKey: () => device?.publicKey ?? new Uint8Array(),
    encryptionPublicKey: () => publicKey,
    verify,
    async seal(recipient, plaintext, context) {
      const message = bytes(plaintext);
      try {
        const sender = await suite.createSenderContext({
          recipientPublicKey: await suite.kem.deserializePublicKey(bytes(recipient)), info: bytes(context)});
        return {encapsulatedKey: bytes(sender.enc), ciphertext: bytes(await sender.seal(message, bytes(context)))};
      } finally { message.fill(0); plaintext.fill(0); }
    },
    async open(enc, ciphertext, context) {
      const receiver = await suite.createRecipientContext({recipientKey: pair.privateKey, enc: bytes(enc), info: bytes(context)});
      return bytes(await receiver.open(bytes(ciphertext), bytes(context)));
    }
  };
}
