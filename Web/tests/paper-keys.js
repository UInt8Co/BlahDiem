import {decode} from './cbor.js';

// Diem's committed vector: the paper words and the Ed25519 device key they derive.
const vector = {
  phrase: 'cute screen devote salt road wet utility shrug physical autumn casino mention clinic inform witness three begin convince truck filter acid wonder record jump',
  publicKey: '5688b04f632fc34bfe48a605e221d0d780ca8ceb4092614bf81d1e7a17803a88'
};

export async function exercisePaperKeys({diem, check, rejects, base, alice, first}) {
  const decode64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
  const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  const fromHex = text => text.match(/../g).map(v => parseInt(v, 16));

  const restored = await diem.paperKeys.restore(vector.phrase);
  check(restored.phrase === vector.phrase && hex(decode64(restored.key.publicKey)) === vector.publicKey, 'Paper key vector');
  const loose = vector.phrase.toUpperCase().replace(/ /g, '\n  ');
  check((await diem.paperKeys.restore(loose)).key.publicKey === restored.key.publicKey, 'Paper key case and spacing');
  const words = vector.phrase.split(' ');
  for(const phrase of [words.slice(1).join(' '), [...words.slice(0, 23), 'acid'].join(' '),
    [...words.slice(0, 23), 'jumpy'].join(' '), 42]) {
    await rejects(() => diem.paperKeys.restore(phrase));
  }
  const fresh = await diem.paperKeys.generate();
  check(fresh.phrase.split(' ').length === 24 && fresh.phrase !== vector.phrase, 'Paper key generation');
  check((await diem.paperKeys.restore(fresh.phrase)).key.publicKey === fresh.key.publicKey, 'Paper key round trip');

  const shape = decode(fresh.device);
  check(shape[2] === 2 && shape[3] === 1 && hex(shape[4]) === hex(decode64(fresh.key.publicKey)), 'Paper device key encoding');
  check(hex(decode((await diem.paperKeys.restore(vector.phrase)).device)[4]) === vector.publicKey, 'Paper device key vector encoding');

  // The identity key certifies the paper like any other Ed25519 device.
  const added = await diem.identityOperation({...base, operation: 'addDevice', profile: first.profile, device: fresh.device}, alice);
  check(added.devices.length === 2, 'Paper key certification');
  const signing = await crypto.subtle.importKey('pkcs8', decode64(fresh.key.privateKey), 'Ed25519', false, ['sign']);
  const paper = {...alice, publicKey: role => role === 'device' ? decode64(fresh.key.publicKey) : new Uint8Array(),
    sign: async(role, bytes) => new Uint8Array(await crypto.subtle.sign('Ed25519', signing, new Uint8Array(bytes)))};
  const asPaper = (operation, profile, extra = {}) => diem.identityOperation({...base, operation, profile, ...extra}, paper);
  const inspected = await asPaper('inspect', added.profile);
  check(inspected.devices.find(device => device.current)?.key.length > 0, 'Paper key signs in');
  // A device key never manages the device set.
  await rejects(() => asPaper('removeDevice', added.profile, {device: fromHex(first.devices[0].id)}));
  const paperID = inspected.devices.find(device => device.current).id;
  const removed = await diem.identityOperation({...base, operation: 'removeDevice', profile: added.profile, device: fromHex(paperID)}, alice);
  await rejects(() => asPaper('inspect', removed.profile));
}
