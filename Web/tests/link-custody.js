import {decode} from './cbor.js';

// Exercise real worker-generated keys through the existing password custody path.
export async function exerciseLinkCustody(diem, check, rejects) {
  const bytes = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const base64 = value => btoa(String.fromCharCode(...value));
  const identity = await diem.generateSigningKey(), device = await diem.generateSigningKey();
  const keys = {identity, device};
  const backend = {
    random: count => crypto.getRandomValues(new Uint8Array(count)),
    publicKey: role => bytes(keys[role].publicKey),
    sign: async(role, message) => new Uint8Array(await crypto.subtle.sign('Ed25519',
      await crypto.subtle.importKey('pkcs8', bytes(keys[role].privateKey), 'Ed25519', false, ['sign']), new Uint8Array(message))),
    verify: async(key, message, signature) => crypto.subtle.verify('Ed25519',
      await crypto.subtle.importKey('raw', new Uint8Array(key), 'Ed25519', false, ['verify']),
      new Uint8Array(signature), new Uint8Array(message))
  };
  const base = {kind: 'user', domain: 'linked.example', dcDomain: 'dc.example', dc: new Uint8Array(32).fill(13),
    generation: '1', now: Math.floor(Date.now() / 1000)};
  let profile = (await diem.identityOperation({...base, operation: 'create', profile: []}, backend)).profile;
  profile = (await diem.identityOperation({...base, operation: 'account', profile, account: '42'}, backend)).profile;
  const owner = await diem.keyFiles.create('owner password');
  const target = await diem.keyFiles.create('new local password');
  const save = () => owner.seal({profile: base64(profile), domain: base.domain, identity, device,
    publisher: 'manual', token: 'portable-token', publicationPending: true});
  try {
    await save();
    for(const transferIdentity of [false, true]) {
      const begun = await diem.deviceLink.begin('Real worker');
      try {
        check(Object.keys(begun.session).join() === 'destroy', 'Link handle exposes no private keys');
        const inspected = await diem.deviceLink.inspect(begun.parameter, begun.request);
        profile = (await diem.identityOperation({...base, operation: 'addDevice', profile, device: inspected.device}, backend)).profile;
        const input = {...begun, profile, domain: base.domain, transferIdentity};
        await rejects(() => owner.respondToDeviceLink(input)); // Must save the revision first.
        await save();
        const response = await owner.respondToDeviceLink(input);
        const opened = await diem.deviceLink.open(begun.session, response, base.dc);
        check(opened.identityKey === transferIdentity, 'Requested custody granted');
        const raw = decode(opened.keyFileContents);
        check(raw[3].length === (transferIdentity ? 2 : 1), 'Only granted private keys enter custody');
        if(transferIdentity) check(decode(opened.metadata)[6] === undefined, 'Publication state does not transfer');
        const file = await target.seal(opened.keyFileContents);
        opened.keyFileContents.fill(0);
        const restored = await target.open(file);
        check(restored.profile === base64(profile), 'Linked custody preserves exact published profile');
        check(!!restored.identity === transferIdentity, 'Custody restores requested authority');
        check(restored.device.publicKey === base64(decode(inspected.device)[4]), 'Custody restores N device key');
        check(restored.publicationPending === false, 'Linked device starts with no pending publication');
        check(restored.token === (transferIdentity ? 'portable-token' : ''), 'Portable settings require identity transfer');
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
  } finally { owner.destroy(); target.destroy(); }
}
