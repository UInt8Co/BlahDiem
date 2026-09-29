import challenge from './challenge.js';
import {createDiem} from '../dist/diem.js';
import {exerciseProfiles} from './profiles.js';

function check(condition, message) { if(!condition) throw new Error(message); }
async function rejects(action) {
  let rejected = false;
  try { await action(); } catch { rejected = true; }
  check(rejected, 'Expected request rejection');
}
async function backend() {
  const keys = {};
  const publicKeys = {};
  for(const role of ['identity', 'device']) {
    keys[role] = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    publicKeys[role] = new Uint8Array(await crypto.subtle.exportKey('raw', keys[role].publicKey));
  }
  return {
    random: length => crypto.getRandomValues(new Uint8Array(length)),
    publicKey: role => publicKeys[role],
    sign: async(role, bytes) => new Uint8Array(await crypto.subtle.sign('Ed25519', keys[role].privateKey, new Uint8Array(bytes))),
    verify: async(key, bytes, signature) => crypto.subtle.verify('Ed25519',
      await crypto.subtle.importKey('raw', new Uint8Array(key), 'Ed25519', false, ['verify']),
      new Uint8Array(signature), new Uint8Array(bytes))
  };
}

export async function run() {
  const diem = await createDiem(new URL('../dist/diem.wasm', import.meta.url));
  const alice = await backend(), bob = await backend();
  const base = {operation: 'create', kind: 'user', domain: 'alice.example.org', profile: [], now: 1_800_000_000,
    dc: Array(32).fill(42), dcDomain: 'dc.example.org', generation: '9007199254740993'};
  const [first, second] = await Promise.all([
    diem.identityOperation(base, alice),
    diem.identityOperation({...base, domain: 'bob.example.org'}, bob)
  ]);
  check(first.id !== second.id && first.namespace !== second.namespace, 'Concurrent signers were mixed');
  const perform = (operation, extra = {}, profile = first.profile) => diem.identityOperation({...base, operation, profile, ...extra}, alice);
  check((await perform('inspect')).id === first.id, 'Profile round trip');
  check(first.domains[0] === base.domain, 'Profile domain order');
  for(const change of [{profileLifetime: 0}, {profileLifetime: 1.5}, {deviceLifetime: 1}, {deviceLifetime: Infinity}]) {
    await rejects(() => perform('renew', change));
  }
  await rejects(() => diem.identityOperation({...base, operation: 'inspect', profile: first.profile}, bob));
  await rejects(() => perform('not-an-operation'));
  await rejects(() => perform('inspect', {now: NaN}));
  for(const domain of ['álîce.example.org', 'alice.例え.org', 'alice.💬.org']) {
    await rejects(() => diem.identityOperation({...base, domain}, alice));
  }
  await rejects(() => diem.identityOperation(base, {...alice, sign: async() => { throw new Error('Signer refused'); }}));
  check((await perform('inspect')).id === first.id, 'Runtime survives backend rejection');
  const extra = {challenge, approvedChallenge: challenge, challengeKind: 'invocation', expiresAt: 1800000060, keyID: '18446744073709551614',
    sessionID: '18446744073709551613', query: [1, 2, 3, 4]};
  check((await perform('prove', extra)).proof.length > 64, 'Bound proof generation');
  for(const change of [{keyID: '1'}, {sessionID: '2'}, {expiresAt: 1800000061}, {now: 1800000061}]) {
    await rejects(() => perform('prove', {...extra, ...change}));
  }
  const numbered = await perform('account', {account: '1000000'});
  check(numbered.account === '1000000', 'Account assignment');
  const renewed = await perform('renew', {now: base.now + 10}, numbered.profile);
  check(first.expiresAt - first.notBefore === 180 * 86400, 'Default profile lifetime');
  check(first.devices[0].expiresAt - first.devices[0].notBefore === 180 * 86400, 'Default device lifetime');
  check(renewed.expiresAt > first.expiresAt, 'Profile renewal');
  const custom = await perform('renew', {now: base.now + 20, profileLifetime: 60 * 86400, deviceLifetime: 90 * 86400}, renewed.profile);
  check(custom.expiresAt - custom.notBefore === 60 * 86400, 'Custom profile lifetime');
  check(custom.devices[0].expiresAt - custom.devices[0].notBefore === 90 * 86400, 'Custom device lifetime');
  const added = await perform('addDevice', {device: second.devices[0].key}, renewed.profile);
  check(added.devices.length === 2, 'Device authorization');
  const device = Array.from(second.devices[0].id.matchAll(/../g), ([hex]) => parseInt(hex, 16));
  const removed = await perform('removeDevice', {device}, added.profile);
  check(removed.devices.length === 1, 'Device revocation');
  // The optimized build must still reject tampered canonical profiles.
  const corrupt = [...removed.profile]; corrupt[corrupt.length - 1] ^= 1;
  await rejects(() => perform('inspect', {}, corrupt));
  await exerciseProfiles({diem, backend, check, rejects, base, alice, first, second});
  check(!('blahCall' in globalThis) && !('blahCrypto' in globalThis), 'Global bridge callbacks leaked');
  return {realm: typeof document === 'undefined' ? 'worker' : 'window', id: first.id};
}
