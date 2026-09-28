import {encode, decode} from './cbor.js';

export async function exerciseProfiles({diem, backend, check, rejects, base, alice, first, second}) {
  const bytes = value => new Uint8Array(value);
  const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  const fromHex = hex => bytes(hex.match(/../g).map(v => parseInt(v, 16)));
  const dc = bytes(base.dc), nonce = new Uint8Array(32).fill(7), expires = base.now + 60;
  const keyID = 18446744073709551614n, sessionID = 18446744073709551613n;
  const content = profile => decode(decode(decode(profile)[4])[0]);
  const data = profile => decode(content(profile)[9]);
  const verify = async(result, signer, statement) => {
    const [message, signature] = decode(result.proof);
    check(await signer.verify(signer.publicKey('device'), message, signature), 'Proof signature');
    const proof = decode(message);
    check(equal(proof[2], fromHex(result.id)), 'Proof identity binding');
    check(equal(proof[4], statement), 'Proof statement binding');
  };
  for(const [kind, tag, domain, account] of [
    ['user', 1, 'person.example.org', '1000000'],
    ['channel', 2, 'channel.example.org', '997852516351'],
    ['bot', 3, 'helperbot.example.org', '1000001'],
    ['stickerSet', 4, 'stickers.example.org', '9223372036854775806']
  ]) {
    const signer = await backend();
    const request = {...base, kind, domain};
    const created = await diem.identityOperation(request, signer);
    check(data(created.profile)[2] === tag, `${kind} profile kind`);
    const perform = (operation, extra = {}, profile = created.profile) =>
      diem.identityOperation({...request, operation, profile, ...extra}, signer);
    await rejects(() => perform('inspect', {kind: kind === 'user' ? 'channel' : 'user'}));
    const numbered = await perform('account', {account});
    check(numbered.account === account, `${kind} account precision`);
    const renewed = await perform('renew', {now: base.now + 10}, numbered.profile);
    check(renewed.id === created.id && renewed.expiresAt > created.expiresAt, `${kind} renewal`);
    const added = await perform('addDevice', {device: second.devices[0].key}, renewed.profile);
    const removed = await perform('removeDevice', {device: fromHex(second.devices[0].id)}, added.profile);
    check(added.devices.length === 2 && removed.devices.length === 1, `${kind} devices`);
    await rejects(() => perform('account', {account: kind === 'channel' ? '997852516352' : '9223372036854775807'}));
    const invocation = encode([4, 1, domain, nonce, expires, dc, keyID, sessionID]);
    const query = bytes([1, 2, 3, 4]);
    const invokeExtra = {challengeKind: 'invocation', challenge: invocation, approvedChallenge: invocation,
      expiresAt: expires, keyID: String(keyID), sessionID: String(sessionID), query};
    const info = diem.inspectChallenge('invocation', invocation);
    check(info.keyID === String(keyID) && info.domain === domain, 'Challenge inspection');
    await verify(await perform('prove', invokeExtra), signer,
      encode([5, 1, bytes(invocation), 1, new Uint8Array(await crypto.subtle.digest('SHA-512', query))]));
    await diem.identityOperation({...request, operation: 'prove', profile: created.profile, ...invokeExtra}, {
      ...signer, publicKey: role => {
        check(role === 'device', 'Proof requested the identity key');
        return signer.publicKey(role);
      }
    });
    await rejects(() => perform('prove', {...invokeExtra, approvedChallenge: []}));
    await rejects(() => perform('prove', {...invokeExtra, dc: Array(32).fill(8)}));

    const profileDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', decode(decode(created.profile)[4])[0]));
    const challenges = [
      ['login', [3, 1, 1, nonce, expires, fromHex(created.id), fromHex(created.devices[0].id), profileDigest,
        base.dcDomain, dc, keyID, sessionID]],
      ['oauthConsent', [6, 1, base.dcDomain, dc, nonce, expires, 42, 'Example app', 9007199254740993n,
        'https://app.example.org/callback', ['openid', 'profile'], 'a'.repeat(43), 'state', 'oidc-nonce']],
      ['accountLink', [8, 1, base.dcDomain, dc, nonce, expires, 3, 1, fromHex(created.id), nonce,
        '9007199254740993', '123', 'External account']],
      ['dcAdmin', [9, 1, base.dcDomain, dc, nonce, expires, 2, 9007199254740993n, bytes([123, 125])]]
    ];
    for(const [challengeKind, fields] of challenges) {
      const challenge = encode(fields);
      const info = diem.inspectChallenge(challengeKind, challenge);
      check(info.dcDomain === base.dcDomain && info.expiresAt === String(expires), 'Approval inspection');
      if(challengeKind === 'oauthConsent') check(info.appVersion === '9007199254740993' && info.scopes.length === 2, 'OAuth fields');
      if(challengeKind === 'accountLink') check(info.externalID === '9007199254740993' && info.operation === 'confirm', 'Account-link fields');
      if(challengeKind === 'dcAdmin') check(info.revision === '9007199254740993' && equal(info.document, bytes([123, 125])), 'DC admin fields');
      const extra = {challengeKind, challenge, approvedChallenge: challenge, expiresAt: expires,
        keyID: String(keyID), sessionID: String(sessionID)};
      await verify(await perform('prove', extra), signer, challenge);
      await rejects(() => perform('prove', {...extra, approvedChallenge: encode([...fields, 0])}));
      await rejects(() => perform('prove', {...extra, now: expires}));
      await rejects(() => perform('prove', {...extra, dcDomain: 'other.example.org'}));
      await rejects(() => diem.inspectChallenge(challengeKind, encode([...fields, 0])));
      if(challengeKind === 'login') {
        await rejects(() => perform('prove', {...extra, keyID: '1'}));
        const wrong = [...fields]; wrong[6] = new Uint8Array(32);
        await rejects(() => perform('prove', {...extra, challenge: encode(wrong), approvedChallenge: encode(wrong)}));
      }
    }
  }

  const dcData = encode([13, 1, 5, ['dc.example.org'], [['dc.example.org', 443, true, 1, '/apiws']],
    [['dc.example.org', 8443, true, 0, null]], 'transport-public-key', 1]);
  const input = {data: dcData, profile: null, now: base.now};
  const created = await diem.dcSetup(input, alice);
  check(data(created.profile)[2] === 5 && created.devices.length === 1, 'DC creation without a server device');
  check(created.devices.every(device => device.notBefore === base.now && device.expiresAt === base.now + 30 * 86400), 'Device validity metadata');
  const renewed = await diem.dcSetup({...input, profile: created.profile, now: base.now + 31 * 86400}, alice);
  check(renewed.id === created.id && renewed.expiresAt > created.expiresAt && renewed.devices.length === 1, 'Expired DC recovery');
  check(equal(content(renewed.profile)[9], bytes(dcData)), 'DC data survives renewal');
  await rejects(() => diem.dcSetup({...input, profile: first.profile}, alice));
  await rejects(() => diem.dcSetup({...input, data: content(first.profile)[9]}, alice));
  await rejects(() => diem.dcSetup({...input, data: new Array(10)}, alice));
  await rejects(() => diem.dcSetup({...input, now: 1.5}, alice));
  const wrongSigner = await backend();
  await rejects(() => diem.dcSetup({...input, profile: created.profile}, wrongSigner));
  const corrupt = [...created.profile]; corrupt[corrupt.length - 1] ^= 1;
  await rejects(() => diem.dcSetup({...input, profile: corrupt}, alice));
}
