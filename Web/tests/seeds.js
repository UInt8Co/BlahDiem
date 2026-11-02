import {decode} from './cbor.js';
import {signers, verify} from './signers.js';

const equal = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

// Persistence exercises CryptoKey structured cloning and encrypted seed custody in each realm.
export async function storedCustody(seed, device, check) {
  const key = await crypto.subtle.generateKey({name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({name: 'AES-GCM', iv}, key, seed);
  const name = `seed-test-${crypto.randomUUID()}`;
  const db = await new Promise((resolve, reject) => {
    const open = indexedDB.open(name, 1);
    open.onupgradeneeded = () => open.result.createObjectStore('custody');
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction('custody', 'readwrite');
      try { tx.objectStore('custody').put({key, iv, ciphertext, device}, 'slot'); }
      catch(error) { reject(new Error(`IndexedDB custody write: ${error.name}: ${error.message}`)); }
      tx.oncomplete = resolve; tx.onerror = () => reject(tx.error);
    });
    const stored = await new Promise((resolve, reject) => {
      const get = db.transaction('custody').objectStore('custody').get('slot');
      get.onsuccess = () => resolve(get.result); get.onerror = () => reject(get.error);
    });
    check(stored.key.extractable === false && stored.device.privateKey.extractable === false, 'IndexedDB keeps non-extractable CryptoKeys');
    const opened = new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: stored.iv}, stored.key, stored.ciphertext));
    check(equal(opened, seed), 'Encrypted seed survives IndexedDB');
    opened.fill(0);
    return stored.device;
  } finally { db.close(); indexedDB.deleteDatabase(name); }
}

export async function exerciseSeeds({diem, check, rejects, base, absent}) {
  const entropy = new Uint8Array(32);
  const words = diem.seeds.words(entropy);
  check(words.length === 24 && words.slice(0, 23).every(word => word === 'abandon') && words[23] === 'art', 'BIP 39 zero entropy');
  check(equal(diem.seeds.restore(` \t${words.join('\n').toUpperCase()}\r\v\f`), entropy), 'Recovery words tolerate ASCII case and whitespace');
  for(const phrase of [words.slice(1).join(' '), [...words, 'art'].join(' '), Array(24).fill('abandon').join(' '),
    words.join(','), words.join(' ').replace('art', 'árt'), words.join(' ').replace('art', 'artt')]) {
    await rejects(() => diem.seeds.restore(phrase));
  }
  for(const value of [new Uint8Array(31), new Uint8Array(33), Array(32).fill(256), new Array(32)]) {
    await rejects(() => diem.seeds.words(value));
    await rejects(() => diem.seeds.identity(value));
  }
  const generated = diem.seeds.generate();
  check(equal(diem.seeds.restore(generated.words.join(' ')), generated.entropy), 'Generated recovery words round trip');
  const identity = await diem.seeds.identity(entropy);
  check(hex(identity.publicKey) === 'a500684469656d2f6b65790103020103010458200fead2e61916099343e4a94f72cbdb30d8ef8fa602740b8c2dc16aecb810e99e', 'Native identity-seed derivation vector');
  check(decode(identity.publicKey)[2] === 1 && decode(identity.publicKey)[3] === 1, 'Identity is purpose-qualified Ed25519');
  check(identity.signer.extractable === false && identity.signer.algorithm.name === 'Ed25519', 'Derived signer is non-extractable');
  check(hex(new Uint8Array(await crypto.subtle.digest('SHA-256', identity.publicKey))) === identity.id, 'Identity ID hashes encoded key');
  check((await diem.seeds.identity(entropy, identity.publicKey)).id === identity.id, 'Identity comparison succeeds');
  await rejects(() => diem.seeds.identity(generated.entropy, identity.publicKey));
  for(const format of ['pkcs8', 'raw', 'jwk']) await rejects(() => crypto.subtle.exportKey(format, identity.signer));
  const device = await diem.deviceKeys.generate();
  check(device.privateKey.extractable === false && device.privateKey.algorithm.name === 'ECDSA' &&
    device.privateKey.algorithm.namedCurve === 'P-256' && device.privateKey.usages.join() === 'sign', 'P-256 device has only non-extractable signing authority');
  check(device.publicKey.length === 65 && device.publicKey[0] === 4, 'Device public key is SEC1');
  for(const format of ['pkcs8', 'raw', 'jwk']) await rejects(() => crypto.subtle.exportKey(format, device.privateKey));
  const persisted = await storedCustody(entropy, device, check);
  const message = new Uint8Array([1, 2, 3]);
  const signature = new Uint8Array(await crypto.subtle.sign({name: 'ECDSA', hash: 'SHA-256'}, persisted.privateKey, message));
  check(signature.length === 64 && await verify(device.publicKey, message, signature), 'Cloned P-256 key signs fixed-width r||s');
  const owner = signers(identity, device);
  const created = await diem.identityOperation({...base, operation: 'create', profile: []}, owner);
  const next = await diem.deviceKeys.generate();
  const recovered = signers(await diem.seeds.identity(diem.seeds.restore(words.join(' ')), identity.publicKey), next);
  const enrolled = await diem.identityOperation({...base, operation: 'enroll', profile: created.profile}, recovered);
  check(enrolled.id === created.id && enrolled.devices.length === 2 && enrolled.devices.some(x => x.current), 'Recovery enrolls a fresh P-256 device');
  await rejects(() => diem.identityOperation({...base, operation: 'enroll', profile: created.profile}, signers(undefined, next)));
  const recoveredLate = await diem.identityOperation({...base, operation: 'enroll',
    profile: created.profile, now: base.now + 200 * 86400}, recovered);
  check(recoveredLate.expiresAt > base.now + 200 * 86400, 'Recovery renews expired profile authority');
  const wrongIdentity = await diem.seeds.identity(generated.entropy);
  await rejects(() => diem.identityOperation({...base, operation: 'enroll', profile: created.profile},
    signers(wrongIdentity, next)));
  absent(generated.entropy);
  generated.entropy.fill(0);
}
