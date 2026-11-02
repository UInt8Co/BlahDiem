import {decode} from './cbor.js';
import {backend as makeBackend, signers} from './signers.js';
import {storedCustody} from './seeds.js';

// Exercise real Window/worker-generated devices without serializing signing secrets.
export async function exerciseLinkCustody(diem, check, rejects, absent, context) {
  const instantiate = WebAssembly.instantiateStreaming;
  const isolated = [];
  if(typeof Worker !== 'function') WebAssembly.instantiateStreaming = async(...args) => {
    const result = await instantiate(...args);
    isolated.push(result.instance.exports.memory);
    return result;
  };
  try { await linkCustody(diem, check, rejects, absent, context); }
  finally { WebAssembly.instantiateStreaming = instantiate; }
  if(typeof Worker !== 'function') {
    check(isolated.length > 0, 'SharedWorker links use separate WASM instances');
    for(const memory of isolated) {
      check(new Uint8Array(memory.buffer).every(byte => byte === 0), 'Disposable link heap is wiped on success, failure and cancellation');
    }
  }
}

async function linkCustody(diem, check, rejects, absent, context) {
  const owner = await makeBackend(diem);
  const base = {kind: 'user', domain: 'linked.example', dcDomain: 'dc.example', dc: new Uint8Array(32).fill(13),
    generation: '1', now: Math.floor(Date.now() / 1000)};
  let profile = (await diem.identityOperation({...base, operation: 'create', profile: []}, owner)).profile;
  profile = (await diem.identityOperation({...base, operation: 'account', profile, account: '42'}, owner)).profile;
  for(const transfer of [false, true]) {
    const begun = await diem.deviceLink.begin('Real worker');
    try {
      check(Object.keys(begun.session).join() === 'destroy', 'Link handle exposes no private keys');
      const inspected = await diem.deviceLink.inspect(begun.parameter, begun.request);
      check(decode(inspected.device)[3] === 2 && inspected.verifies.join() === '1,2', 'Joining device is P-256 and verifies both algorithms');
      const input = {code: begun.parameter, request: begun.request, profile, domain: base.domain};
      await rejects(() => diem.deviceLink.respond(input)); // Profile must certify the new key.
      profile = (await diem.identityOperation({...base, operation: 'addDevice', profile, device: inspected.device}, owner)).profile;
      const metadata = new Uint8Array([0, 255, 1]);
      const response = await diem.deviceLink.respond({...input, profile,
        seed: transfer ? owner.seed : undefined, metadata: transfer ? metadata : undefined});
      const opened = await diem.deviceLink.open(begun.session, response, base.dc);
      check(!!opened.seed === transfer, 'Seed transfer requires explicit approval');
      check(opened.device.privateKey.extractable === false, 'Joining signer stays non-extractable after worker completion');
      check(JSON.stringify(Array.from(opened.device.publicKey)) === JSON.stringify(Array.from(decode(inspected.device)[4])), 'Returned signer matches requested device');
      if(transfer) {
        check(opened.seed.every((v, i) => v === owner.seed[i]), 'Grant transfers the root entropy');
        check(opened.metadata.every((v, i) => v === metadata[i]), 'Opaque metadata preserved');
      } else check(opened.metadata === undefined, 'Device-only grant carries no metadata');
      const persisted = await storedCustody(opened.seed ?? new Uint8Array(32), opened.device, check, context);
      const identity = opened.seed ? await diem.seeds.identity(opened.seed) : undefined;
      const linked = signers(identity, persisted);
      const inspectedProfile = await diem.identityOperation({...base, operation: 'inspect', profile}, linked);
      check(inspectedProfile.devices.some(x => x.current), 'Custodied joining signer opens its certified profile');
      if(transfer) {
        const renewed = await diem.identityOperation({...base, operation: 'renew', profile, now: base.now + 1}, linked);
        check(renewed.id === inspectedProfile.id, 'Transferred seed manages the identity');
      } else {
        await rejects(() => diem.identityOperation({...base, operation: 'addDevice', profile, device: owner.device.publicKey}, linked));
      }
      opened.seed?.fill(0);
      await rejects(() => diem.deviceLink.open(begun.session, response, base.dc));
    } finally { begun.session.destroy(); }
  }
  const failed = await diem.deviceLink.begin('Failure is fatal');
  await rejects(() => diem.deviceLink.open(failed.session, new Uint8Array(65537), base.dc));
  await rejects(() => diem.deviceLink.open(failed.session, [], base.dc));
  failed.session.destroy();
  const cancelled = await diem.deviceLink.begin('Cancelled');
  cancelled.session.destroy();
  await rejects(() => diem.deviceLink.open(cancelled.session, [], base.dc));
  absent(owner.seed);
  owner.seed.fill(0);
}
