import challenge from './challenge.js';
import {encode, decode} from './cbor.js';
import {createDiem} from '../dist/diem.js';
import {exerciseProfiles} from './profiles.js';
import {backend as makeBackend, signers} from './signers.js';
import {exerciseLinkCustody} from './link-custody.js';

// Blah's operations in its runtime. Diem's web tests cover seeds, custody, hosting and
// generic device linking; these check Blah's use of them through this one WASM.

function check(condition, message) { if(!condition) throw new Error(message); }
async function rejects(action) {
  let rejected = false;
  try { await action(); } catch { rejected = true; }
  check(rejected, 'Expected request rejection');
}
export async function run({engine, realm}) {
  const instantiate = WebAssembly.instantiateStreaming;
  let memory, diem;
  WebAssembly.instantiateStreaming = async(...args) => {
    const result = await instantiate(...args);
    memory = result.instance.exports.memory;
    return result;
  };
  try { diem = await createDiem(new URL('../dist/diem.wasm', import.meta.url)); }
  finally { WebAssembly.instantiateStreaming = instantiate; }
  const absent = seed => {
    const heap = new Uint8Array(memory.buffer);
    for(let offset = heap.indexOf(seed[0]); offset >= 0; offset = heap.indexOf(seed[0], offset + 1)) {
      check(!seed.every((byte, index) => heap[offset + index] === byte), 'Identity entropy retained in the main WASM heap');
    }
  };
  const backend = () => makeBackend(diem);
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
  const domains = ['alice.example.org', 'second.example.org', 'discovery.example.org'];
  const claimed = await perform('domains', {domains});
  check(JSON.stringify(claimed.domains) === JSON.stringify(domains), 'Ordered domain editing');
  check(!('usernameDomains' in claimed), 'No username flag API');
  const hidden = await perform('domains', {domains: domains.slice(1)}, claimed.profile);
  check(hidden.domains.length === 2, 'Remove a profile domain');
  check((await perform('inspect', {domain: domains[1]}, hidden.profile)).id === first.id, 'Changed discovery domain retains identity');
  for(const change of [
    {domains: []},
    {domains: [base.domain, base.domain]},
    {domains: ['bad_domain.example.org']}
  ]) await rejects(() => perform('domains', change));
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
  // A native Secure Enclave device uses P-256, including its profile signature.
  const p256 = await crypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, false, ['sign']);
  const keyShape = decode(second.devices[0].key);
  keyShape[3] = 2;
  keyShape[4] = new Uint8Array(await crypto.subtle.exportKey('raw', p256.publicKey));
  const nativeKey = encode(keyShape);
  const native = await perform('addDevice', {device: nativeKey}, removed.profile);
  const envelope = decode(native.profile);
  const signed = decode(envelope[4]);
  const fields = decode(signed[0]);
  fields[4] = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(nativeKey)));
  const message = new Uint8Array(encode(fields));
  const signature = new Uint8Array(await crypto.subtle.sign({name: 'ECDSA', hash: 'SHA-256'}, p256.privateKey, message));
  envelope[4] = new Uint8Array(encode({0: message, 1: signature}));
  const inspected = await perform('inspect', {}, encode(envelope));
  check(inspected.devices.length === 2, 'Secure Enclave profile verification');
  const publicNative = await diem.verifyProfile(encode(envelope), base.now, {verify: alice.verify});
  check(publicNative.id === native.id && publicNative.kind === 'user' && !publicNative.lapsed,
    'Public P-256 profile verification');
  // The optimized build must still reject tampered canonical profiles.
  const corrupt = [...removed.profile]; corrupt[corrupt.length - 1] ^= 1;
  await rejects(() => perform('inspect', {}, corrupt));
  await exerciseProfiles({diem, backend, check, rejects, base, alice, first, second});
  await exerciseKinds({diem, check, base, alice});
  await exerciseRecovery({diem, check, rejects, base, absent});
  await exerciseLinkCustody(diem, check, rejects, absent);
  check(!('blahCall' in globalThis) && !('blahCrypto' in globalThis), 'Global bridge callbacks leaked');
  absent(alice.seed); absent(bob.seed);
  return {realm: typeof document === 'undefined' ? 'worker' : 'window', id: first.id};
}

// Domain edits keep each kind, and Diem's hosting client runs from Blah's WASM.
async function exerciseKinds({diem, check, base, alice}) {
  const utf8 = text => new TextEncoder().encode(text);
  const policy = {domain: 'id.example', labelPattern: '[a-z0-9-]+', maxClaimsPerIdentity: 3,
    maxUpdatesPerIdentityPerHour: 12, claimGraceAfterExpiry: 2_592_000,
    proofOfWork: {algorithm: 'sha256-leading-zero-bits-v1', baseBits: 4, bitsPerShorterCharacter: 0, referenceLength: 8}};
  const transport = async() => ({status: 200, headers: {}, body: utf8(JSON.stringify(policy))});
  const fetched = await diem.hosting.policy('id.example', transport);
  check(fetched.domain === 'id.example' && fetched.names.maxClaimsPerIdentity === 3, 'Hosting policy through Blah\'s runtime');
  for(const kind of ['bot', 'channel', 'stickerSet']) {
    const created = await diem.identityOperation({...base, kind}, alice);
    const domains = kind === 'stickerSet' ? ['kind.id.example'] : [base.domain, 'kind.id.example'];
    const changed = await diem.identityOperation({...base, kind, operation: 'domains', profile: created.profile, domains}, alice);
    const info = await diem.verifyProfile(changed.profile, base.now, alice);
    check(info.kind === kind && info.domains.join() === domains.join(), 'Domains preserve ' + kind);
  }
}

// Recovery: the restored seed enrolls a fresh device into the Blah profile.
async function exerciseRecovery({diem, check, rejects, base, absent}) {
  const generated = diem.seeds.generate();
  const identity = await diem.seeds.identity(generated.entropy);
  const created = await diem.identityOperation({...base, operation: 'create', profile: []},
    signers(identity, await diem.deviceKeys.generate()));
  const next = await diem.deviceKeys.generate();
  const recovered = signers(await diem.seeds.identity(diem.seeds.restore(generated.words.join(' ')), identity.publicKey), next);
  const enrolled = await diem.identityOperation({...base, operation: 'enroll', profile: created.profile}, recovered);
  check(enrolled.id === created.id && enrolled.devices.length === 2 && enrolled.devices.some(x => x.current), 'Recovery enrolls a fresh P-256 device');
  await rejects(() => diem.identityOperation({...base, operation: 'enroll', profile: created.profile}, signers(undefined, next)));
  const recoveredLate = await diem.identityOperation({...base, operation: 'enroll',
    profile: created.profile, now: base.now + 200 * 86400}, recovered);
  check(recoveredLate.expiresAt > base.now + 200 * 86400, 'Recovery renews expired profile authority');
  const wrongIdentity = await diem.seeds.identity(diem.seeds.generate().entropy);
  await rejects(() => diem.identityOperation({...base, operation: 'enroll', profile: created.profile},
    signers(wrongIdentity, next)));
  absent(generated.entropy);
  generated.entropy.fill(0);
}
