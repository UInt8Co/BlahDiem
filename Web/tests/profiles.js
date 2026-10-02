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
    const {0: message, 1: signature} = decode(result.proof);
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
    const invocation = encode({0: 4, 1: 1, 2: domain, 3: nonce, 4: expires, 5: dc, 6: keyID, 7: sessionID});
    const query = bytes([1, 2, 3, 4]);
    const invokeExtra = {challengeKind: 'invocation', challenge: invocation, approvedChallenge: invocation,
      expiresAt: expires, keyID: String(keyID), sessionID: String(sessionID), query};
    const info = diem.inspectChallenge('invocation', invocation);
    check(info.keyID === String(keyID) && info.domain === domain, 'Challenge inspection');
    await verify(await perform('prove', invokeExtra), signer,
      encode({0: 5, 1: 1, 2: bytes(invocation), 3: 1, 4: new Uint8Array(await crypto.subtle.digest('SHA-512', query))}));
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
      ['login', {0: 3, 1: 1, 2: 1, 3: nonce, 4: expires, 5: fromHex(created.id), 6: fromHex(created.devices[0].id), 7: profileDigest, 8: base.dcDomain, 9: dc, 10: keyID, 11: sessionID}],
      ['oauthConsent', {0: 6, 1: 1, 2: base.dcDomain, 3: dc, 4: nonce, 5: expires, 6: 42, 7: 'Example app', 8: 9007199254740993n, 9: 'https://app.example.org/callback', 10: ['openid', 'profile'], 11: 'a'.repeat(43), 12: 'state', 13: 'oidc-nonce'}],
      ['accountLink', {0: 8, 1: 1, 2: base.dcDomain, 3: dc, 4: nonce, 5: expires, 6: 3, 7: 1, 8: fromHex(created.id), 9: nonce, 10: '9007199254740993', 11: '123', 12: 'External account'}],
      ['dcAdmin', {0: 9, 1: 1, 2: base.dcDomain, 3: dc, 4: nonce, 5: expires, 6: 2, 7: 9007199254740993n, 8: bytes([123, 125])}]
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
      await rejects(() => perform('prove', {...extra, approvedChallenge: encode({...fields, 100: 0})}));
      await rejects(() => perform('prove', {...extra, now: expires}));
      await rejects(() => perform('prove', {...extra, dcDomain: 'other.example.org'}));
      diem.inspectChallenge(challengeKind, encode({...fields, 100: 0}));
      const extended = encode({...fields, 100: 0});
      await verify(await perform('prove', {...extra, challenge: extended, approvedChallenge: extended}), signer, extended);
      if(challengeKind === 'login') {
        await rejects(() => perform('prove', {...extra, keyID: '1'}));
        const wrong = {...fields}; wrong[6] = new Uint8Array(32);
        await rejects(() => perform('prove', {...extra, challenge: encode(wrong), approvedChallenge: encode(wrong)}));
      }
    }
  }

  const dcData = encode({0: 13, 1: 1, 2: 5, 3: ['dc.example.org'], 4: [{0: 'dc.example.org', 1: 443, 2: true, 3: 1, 4: '/apiws'}],
    5: [{0: 'dc.example.org', 1: 8443, 2: true, 3: 0, 4: null}], 6: 'transport-public-key', 7: 1});
  const input = {data: dcData, profile: null, now: base.now};
  const created = await diem.dcSetup(input, alice);
  check(data(created.profile)[2] === 5 && created.devices.length === 1, 'DC creation without a server device');
  const dcRequest = {...base, kind: 'user', domain: 'dc.example.org', dcDomain: 'dc.example.org',
    dc: fromHex(created.id), profile: created.profile};
  const operateDC = (operation, extra = {}) => diem.identityOperation({...dcRequest, operation, ...extra}, alice);
  const account = await operateDC('inspect');
  check(account.account === '777000' && account.id === created.id, 'DC is a fixed user account');
  await operateDC('inspect', {kind: 'dc'});
  const dcInvocation = encode({0: 4, 1: 1, 2: dcRequest.domain, 3: nonce, 4: expires,
    5: fromHex(created.id), 6: keyID, 7: sessionID});
  const dcQuery = bytes([1, 2, 3, 4]);
  await verify(await operateDC('prove', {challengeKind: 'invocation', challenge: dcInvocation,
    approvedChallenge: dcInvocation, expiresAt: expires, keyID: String(keyID), sessionID: String(sessionID),
    query: dcQuery}), alice, encode({0: 5, 1: 1, 2: bytes(dcInvocation), 3: 1,
    4: new Uint8Array(await crypto.subtle.digest('SHA-512', dcQuery))}));
  const dcRenewed = await operateDC('renew', {now: base.now + 10});
  check(data(dcRenewed.profile)[2] === 5 && dcRenewed.account === '777000', 'User renewal preserves DC kind');
  await rejects(() => operateDC('account', {account: '1000000'}));
  await rejects(() => operateDC('inspect', {dc: base.dc}));
  check(created.expiresAt === base.now + 90 * 86400, 'Default 90-day DC profile');
  check(created.devices.every(device => device.notBefore === base.now && device.expiresAt === base.now + 90 * 86400), 'Default 90-day DC certificate');
  const discovered = await diem.verifyDCProfile('dc.example.org', created.profile, base.now, {verify: alice.verify});
  check(discovered.id === created.id && discovered.namespaceGeneration === '1', 'Verified DC identity and namespace');
  check(discovered.endpoints[0].path === '/apiws' && discovered.endpoints[0].transport === 'webSocket', 'Verified DC endpoints');
  for(const [domain, profile, now] of [
    ['other.example.org', created.profile, base.now],
    ['dc.example.org', first.profile, base.now],
    ['dc.example.org', created.profile, base.now - 1],
    ['dc.example.org', created.profile, created.expiresAt]
  ]) await rejects(() => diem.verifyDCProfile(domain, profile, now, {verify: alice.verify}));
  await rejects(() => diem.verifyDCProfile('dc.example.org', created.profile, base.now, {verify: async() => false}));
  const changed = [...created.profile]; changed[changed.length - 1] ^= 1;
  await rejects(() => diem.verifyDCProfile('dc.example.org', changed, base.now, {verify: alice.verify}));
  const renewed = await diem.dcSetup({...input, profile: created.profile, now: base.now + 91 * 86400,
    profileLifetime: 45 * 86400, deviceLifetime: 120 * 86400}, alice);
  check(renewed.id === created.id && renewed.expiresAt > created.expiresAt && renewed.devices.length === 1, 'Expired DC recovery');
  check(equal(content(renewed.profile)[9], bytes(dcData)), 'DC data survives renewal');
  check(renewed.expiresAt === base.now + (91 + 45) * 86400, 'Chosen DC profile lifetime');
  check(renewed.devices[0].expiresAt === base.now + (91 + 120) * 86400, 'Chosen DC certificate lifetime');
  for(const lifetimes of [
    {profileLifetime: 0}, {deviceLifetime: 0}, {profileLifetime: -1}, {deviceLifetime: 1.5},
    {profileLifetime: 121 * 86400, deviceLifetime: 120 * 86400},
    {deviceLifetime: Number.MAX_SAFE_INTEGER}
  ]) await rejects(() => diem.dcSetup({...input, ...lifetimes}, alice));
  await rejects(() => diem.dcSetup({...input, profile: first.profile}, alice));
  await rejects(() => diem.dcSetup({...input, data: content(first.profile)[9]}, alice));
  await rejects(() => diem.dcSetup({...input, data: new Array(10)}, alice));
  await rejects(() => diem.dcSetup({...input, now: 1.5}, alice));
  const wrongSigner = await backend();
  await rejects(() => diem.dcSetup({...input, profile: created.profile}, wrongSigner));
  const corrupt = [...created.profile]; corrupt[corrupt.length - 1] ^= 1;
  await rejects(() => diem.dcSetup({...input, profile: corrupt}, alice));
}
