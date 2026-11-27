import {encode, decode} from './cbor.js';

export async function exerciseProfiles({diem, backend, check, rejects, base, alice, first, second}) {
  const bytes = value => new Uint8Array(value);
  const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  const fromHex = hex => bytes(hex.match(/../g).map(v => parseInt(v, 16)));
  const dc = bytes(base.dc), nonce = new Uint8Array(32).fill(7), expires = base.now + 60;
  const keyID = 18446744073709551614n, sessionID = 18446744073709551613n;
  const content = profile => decode(decode(decode(profile)[4])[0]);
  // Blah's map in the profile content.
  const blah = profile => content(profile)['com.blahim'];
  // Profile domains (9) and application fields (reverse-DNS keys), as signed in the content.
  const fields = profile => Object.fromEntries(Object.entries(content(profile)).filter(([key]) => key == 9 || !/^\d+$/.test(key)));
  const publicCrypto = {verify: alice.verify};
  const publicInfo = (profile, now = base.now) => diem.verifyProfile(profile, now, publicCrypto);
  const rejectsWith = async(action, message) => {
    try { await action(); } catch(error) {
      check(String(error).includes(message), `Expected ${message}, got ${error}`);
      return;
    }
    throw new Error(`Expected ${message} rejection`);
  };
  // Independently re-sign fixtures to distinguish structural checks from signature checks.
  const resign = async(profile, signer, change) => {
    const envelope = decode(profile), signed = decode(envelope[4]), fields = decode(signed[0]);
    change(fields);
    signed[0] = bytes(encode(fields));
    signed[1] = await signer.sign('device', signed[0]);
    envelope[4] = bytes(encode(signed));
    return encode(envelope);
  };
  const verify = async(result, signer, statement) => {
    const {0: message, 1: signature} = decode(result.proof);
    check(await signer.verify(signer.publicKey('device'), message, signature), 'Proof signature');
    const proof = decode(message);
    check(proof[0] === 'Diem/proof' && proof[1] === 4 && Object.keys(proof).join() === '0,1,2,3,com.blahim', 'Proof layout');
    check(equal(proof[2], fromHex(result.id)), 'Proof identity binding');
    // The com.blahim value is the statement's record map; it re-encodes to the exact bytes.
    check(equal(encode(proof['com.blahim']), statement), 'Proof statement binding');
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
    check(blah(created.profile)[0] === tag && content(created.profile)[9][0] === domain, `${kind} profile kind`);
    const perform = (operation, extra = {}, profile = created.profile) =>
      diem.identityOperation({...request, operation, profile, ...extra}, signer);
    await rejects(() => perform('inspect', {kind: kind === 'user' ? 'channel' : 'user'}));
    const numbered = await perform('account', {account});
    check(numbered.account === account, `${kind} account precision`);
    const publicProfile = await publicInfo(bytes(numbered.profile));
    check(publicProfile.id === created.id && publicProfile.kind === kind, `${kind} verified public identity`);
    check(publicProfile.generation === String(content(numbered.profile)[3]) &&
      publicProfile.revision === String(content(numbered.profile)[5]), `${kind} public version`);
    check(publicProfile.notBefore === String(numbered.notBefore) && publicProfile.expiresAt === String(numbered.expiresAt) && !publicProfile.lapsed,
      `${kind} public validity`);
    check(publicProfile.domains.length === 1 && publicProfile.domains[0] === domain &&
      publicProfile.home.dc === Array.from(dc, v => v.toString(16).padStart(2, '0')).join('') &&
      publicProfile.home.account === account && publicProfile.home.epoch === '1', `${kind} public home and domains`);
    check((await publicInfo(created.profile)).home.account === null, `${kind} unallocated account`);
    for(const [now, lapsed] of [[numbered.notBefore - 1, true], [numbered.notBefore, false],
      [numbered.expiresAt - 1, false], [numbered.expiresAt, true], [numbered.expiresAt + 1, true]]) {
      check((await publicInfo(numbered.profile, now)).lapsed === lapsed, `${kind} validity boundary ${now}`);
    }
    const badSignature = decode(numbered.profile), signed = decode(badSignature[4]);
    signed[1][0] ^= 1; badSignature[4] = bytes(encode(signed));
    await rejectsWith(() => publicInfo(encode(badSignature)), 'invalidSignature');
    const badCertificate = decode(numbered.profile), certificate = decode(badCertificate[3][0]);
    certificate[1][0] ^= 1; badCertificate[3][0] = bytes(encode(certificate));
    await rejectsWith(() => publicInfo(encode(badCertificate)), 'invalidSignature');
    const invalidKind = await resign(numbered.profile, signer, fields => { fields['com.blahim'][0] = 99; });
    await rejectsWith(() => publicInfo(invalidKind), 'invalidProfile');
    if(kind === 'user') {
      const domains = ['z.example.org', domain, 'a.example.org'];
      const ordered = await perform('domains', {domains}, numbered.profile);
      check(JSON.stringify((await publicInfo(ordered.profile)).domains) === JSON.stringify(domains), 'Public domain order');
      const noHome = await resign(numbered.profile, signer, fields => { fields['com.blahim'][1] = null; });
      check((await publicInfo(noHome)).home === null, 'Absent public home');
      const bigEpoch = await resign(numbered.profile, signer, fields => { fields['com.blahim'][1][1] = 9007199254740993n; });
      check((await publicInfo(bigEpoch)).home.epoch === '9007199254740993', 'Public epoch precision');
      for(const change of [fields => { fields[5] = 0; }, fields => { fields[6] = new Uint8Array(); },
        fields => { fields[3] = 2; }, fields => { fields[8] = numbered.expiresAt + 1; }]) {
        const invalid = await resign(numbered.profile, signer, change);
        await rejects(() => publicInfo(invalid));
      }
      const invalidHome = await resign(numbered.profile, signer, fields => { fields['com.blahim'][1][1] = 0; });
      await rejectsWith(() => publicInfo(invalidHome), 'invalidProfile');
      // Custody works on any DC; acting as or numbering an account needs its home.
      const otherDC = Array(32).fill(8), otherHex = '08'.repeat(32);
      const elsewhere = await perform('inspect', {dc: otherDC}, numbered.profile);
      check(elsewhere.id === created.id && elsewhere.namespace === '' && elsewhere.account === account &&
        equal(elsewhere.profile, numbered.profile), 'Inspect away from home');
      check(numbered.namespace !== '', 'Namespace at home');
      const renewedElsewhere = await perform('renew', {dc: otherDC, now: base.now + 5}, numbered.profile);
      check((await publicInfo(renewedElsewhere.profile)).home.account === account, 'Renewal away from home keeps the hosting');
      await rejectsWith(() => perform('account', {dc: otherDC, account}, numbered.profile), 'wrongHome');
      await rejectsWith(() => perform('home', {}, numbered.profile), 'wrongHome');
      const moved = await perform('home', {dc: otherDC}, numbered.profile);
      const movedInfo = await publicInfo(moved.profile);
      check(moved.account === '' && moved.namespace !== '' && moved.namespace !== numbered.namespace &&
        movedInfo.home.dc === otherHex && movedInfo.home.epoch === '2' && movedInfo.home.account === null, 'Home change starts a new hosting');
      check((await perform('inspect', {}, moved.profile)).namespace === '', 'Former home has no namespace');
    }
    if(kind !== 'user') await rejectsWith(() => perform('home', {dc: Array(32).fill(8)}), 'wrongHome');
    const renewed = await perform('renew', {now: base.now + 10}, numbered.profile);
    check(renewed.id === created.id && renewed.expiresAt > created.expiresAt, `${kind} renewal`);
    const added = await perform('addDevice', {device: second.devices[0].key}, renewed.profile);
    const removed = await perform('removeDevice', {device: fromHex(second.devices[0].id)}, added.profile);
    check(added.devices.length === 2 && removed.devices.length === 1, `${kind} devices`);
    const addedInfo = await publicInfo(added.profile), removedInfo = await publicInfo(removed.profile);
    check(BigInt(removedInfo.generation) > BigInt(addedInfo.generation) &&
      BigInt(removedInfo.revision) > BigInt(addedInfo.revision), `${kind} public version after revocation`);
    const untrustedDevice = decode(added.profile), otherCertificate = decode(untrustedDevice[3][1]);
    otherCertificate[1][0] ^= 1; untrustedDevice[3][1] = bytes(encode(otherCertificate));
    await rejectsWith(() => publicInfo(encode(untrustedDevice)), 'invalidSignature');
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

  {
    // Application profiles: a user fixture re-signed with application content.
    const signer = await backend();
    const request = {...base, kind: 'user', domain: 'app.example.org'};
    const user = await diem.identityOperation(request, signer);
    const asApplication = (application, domains) => resign(user.profile, signer, fields => {
      if(domains) fields[9] = domains;
      fields['com.blahim'] = {0: 6, ...application};
    });
    const key32 = new Uint8Array(32).fill(5), key65 = new Uint8Array(65).fill(6); key65[0] = 4;
    const full = {2: 'Example App', 3: 'https://app.example.org/download', 4: {0: new Uint8Array(32).fill(1), 1: dc},
      5: {0: false, 1: ['https://app.example.org/cb', 'example-app://cb'],
        2: [{0: 'ed', 1: 1, 2: key32}, {0: 'es', 1: 2, 2: key65}]},
      6: {0: 'https://push.example.org/credentials', 1: {0: 'org.example.app', 1: 'https://push.example.org/apns',
        2: 'https://push.example.org/apns-sandbox'}, 2: {0: 'https://push.example.org/web', 1: key65}},
      7: [1, 9007199254740993n]};
    const profile = await asApplication(full);
    const info = await publicInfo(profile);
    check(info.kind === 'application' && info.id === user.id && info.home === null &&
      info.domains.length === 1 && info.domains[0] === 'app.example.org', 'Application profile facts');
    const application = info.application;
    check(application.name === 'Example App' && application.downloadURL === 'https://app.example.org/download' &&
      application.bot.id === '01'.repeat(32) && application.bot.dc === base.dc.map(v => v.toString(16).padStart(2, '0')).join('') &&
      JSON.stringify(application.versions) === JSON.stringify(['1', '9007199254740993']), 'Application name, bot and versions');
    check(application.oauth.publicClient === false && application.oauth.redirectURIs.length === 2 &&
      application.oauth.clientKeys.length === 2 && application.oauth.clientKeys[0].algorithm === 'EdDSA' &&
      equal(bytes(application.oauth.clientKeys[0].publicKey), key32) && application.oauth.clientKeys[1].algorithm === 'ES256' &&
      application.oauth.clientKeys[1].keyID === 'es', 'Application OAuth');
    check(application.push.credentialsURL === 'https://push.example.org/credentials' &&
      application.push.apns.topic === 'org.example.app' && application.push.apns.sandboxURL === 'https://push.example.org/apns-sandbox' &&
      application.push.webPush.proxyURL === 'https://push.example.org/web' &&
      equal(bytes(application.push.webPush.vapidPublicKey), key65), 'Application push');
    const minimal = await publicInfo(await asApplication({2: 'Minimal', 3: null, 4: null, 5: null, 6: null, 7: null}));
    check(minimal.application.downloadURL === null && minimal.application.bot === null && minimal.application.oauth === null &&
      minimal.application.push === null && minimal.application.versions === null, 'Absent application fields');
    check((await publicInfo(await asApplication({...full, 7: []}))).application.versions.length === 0, 'Empty versions');
    check((await publicInfo(await asApplication({...full, 7: [-5, 0]}))).application.versions[0] === '-5', 'Negative version');
    check(info.application !== null && (await publicInfo(user.profile)).application === null, 'Content only for applications');
    for(const bad of [{...full, 3: 'http://app.example.org/'}, {...full, 7: [2, 2]}, {...full, 7: [3, 1]},
      {...full, 2: ''}, {...full, 5: {...full[5], 1: []}}, {...full, 5: {...full[5], 2: [full[5][2][0], full[5][2][0]]}},
      {...full, 6: {...full[6], 2: {0: 'https://push.example.org/web', 1: key32}}}, {...full, 4: {0: new Uint8Array(31), 1: dc}}]) {
      await rejectsWith(async() => publicInfo(await asApplication(bad)), 'invalidProfile');
    }
    await rejectsWith(async() => publicInfo(await asApplication({2: 'Missing'})), 'invalidProfile');
    // The wire pair is derived natively; recompute SHA-256("Blah/app-id:1" || id) independently.
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256',
      new Uint8Array([...new TextEncoder().encode('Blah/app-id:1'), ...fromHex(info.id)])));
    const apiID = ((digest[0] << 24 | digest[1] << 16 | digest[2] << 8 | digest[3]) & 0x3fffffff) + 0x40000000;
    const apiHash = Array.from(digest.slice(4, 20), v => v.toString(16).padStart(2, '0')).join('');
    const pair = diem.applicationWirePair(info);
    check(pair.apiID === apiID && pair.apiHash === apiHash && apiID >= 0x40000000 && apiHash.length === 32, 'Application wire pair');
    check(typeof pair.apiID === 'number', 'Wire pair api_id is a number');
    const fromID = diem.applicationWirePair(info.id);
    check(fromID.apiID === apiID && fromID.apiHash === apiHash, 'Wire pair from an identity');
    for(const invalid of [await publicInfo(user.profile), {kind: 'application', id: 'xyz'}, info.id.toUpperCase(), info.id.slice(2),
      '', null, undefined, 5, {id: info.id}]) {
      let thrown = false;
      try { diem.applicationWirePair(invalid); } catch(error) { thrown = error instanceof TypeError; }
      check(thrown, 'Wire pair rejects non-application input');
    }
  }

  // `create` with caller-supplied fields keeps the content, re-stamping only the home expiry.
  {
    const signer = await backend();
    const home = {0: bytes(dc), 1: 7, 2: 1, 3: 4242};
    const given = {9: ['moved.example.org', 'other.example.org'], 'com.blahim': {0: 1, 1: home}};
    const request = {...base, kind: 'user', domain: 'moved.example.org', fields: encode(given)};
    const adopted = await diem.identityOperation(request, signer);
    const map = blah(adopted.profile);
    check(map[1][1] === 7 && map[1][3] === 4242 && map[1][2] === base.now + 180 * 86400, 'Create adopts supplied home');
    check(adopted.domains.join() === 'moved.example.org,other.example.org' && adopted.account === '4242', 'Create adopts supplied domains');
    await rejects(() => diem.identityOperation({...request, kind: 'channel'}, signer));
    await rejects(() => diem.identityOperation({...request, domain: 'unlisted.example.org'}, signer));
  }

  // DC setup data: domains (9) and Blah's map, which a DC profile signs as given.
  const dcData = encode({9: ['dc.example.org'], 'com.blahim': {0: 5, 2: [{0: 'dc.example.org', 1: 443, 2: true, 3: 1, 4: '/apiws'}],
    3: [{0: 'dc.example.org', 1: 8443, 2: true, 3: 0, 4: null}], 4: 'transport-public-key', 5: 1}});
  const input = {data: dcData, profile: null, seed: alice.seed, device: alice.device, now: base.now};
  const created = await diem.dcSetup(input);
  check(blah(created.profile)[0] === 5 && created.devices.length === 1, 'DC creation without a server device');
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
  check(blah(dcRenewed.profile)[0] === 5 && dcRenewed.account === '777000', 'User renewal preserves DC kind');
  await rejects(() => operateDC('account', {account: '1000000'}));
  check((await operateDC('inspect', {dc: base.dc})).namespace === '', 'DC inspected away from itself');
  await rejects(() => operateDC('home', {dc: base.dc}));
  await rejects(() => operateDC('prove', {dc: base.dc, challengeKind: 'invocation', challenge: dcInvocation,
    approvedChallenge: dcInvocation, expiresAt: expires, keyID: String(keyID), sessionID: String(sessionID), query: dcQuery}));
  check(created.expiresAt === base.now + 90 * 86400, 'Default 90-day DC profile');
  check(created.devices.every(device => device.notBefore === base.now && device.expiresAt === base.now + 90 * 86400), 'Default 90-day DC certificate');
  const discovered = await diem.verifyDCProfile('dc.example.org', created.profile, base.now, {verify: alice.verify});
  const publicDC = await publicInfo(created.profile);
  check(publicDC.kind === 'dc' && publicDC.id === created.id && publicDC.home.dc === created.id &&
    publicDC.home.account === '777000' && publicDC.home.epoch === '1', 'Public DC self-hosting');
  check((await publicInfo(created.profile, created.expiresAt)).lapsed, 'Lapsed public DC verifies');
  await rejectsWith(() => diem.verifyProfile(created.profile, base.now, {verify: async() => false}), 'invalidSignature');
  for(const now of [-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    await rejectsWith(() => publicInfo(created.profile, now), 'Invalid profile verification request');
  }
  for(const profile of [[], [256], [-1], [1.5], new Array(10), new Uint8Array(100001)]) {
    await rejects(() => publicInfo(profile));
  }
  await rejectsWith(() => diem.verifyProfile(created.profile, base.now, {}), 'Invalid profile verification request');
  // BridgeJS preserves backend exceptions, whose stack formatting differs by browser.
  await rejects(() => diem.verifyProfile(created.profile, base.now, {verify: async() => { throw new Error('Verifier refused'); }}));
  const concurrent = await Promise.allSettled([publicInfo(created.profile),
    diem.verifyProfile(first.profile, base.now, {verify: async() => false}), publicInfo(first.profile)]);
  check(concurrent[0].status === 'fulfilled' && concurrent[1].status === 'rejected' &&
    concurrent[2].status === 'fulfilled', 'Public verification callbacks stay per operation');
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
    profileLifetime: 45 * 86400, deviceLifetime: 120 * 86400});
  check(renewed.id === created.id && renewed.expiresAt > created.expiresAt && renewed.devices.length === 1, 'Expired DC recovery');
  const freshDevice = await diem.deviceKeys.generate();
  const fresh = await diem.dcSetup({...input, device: freshDevice, profile: created.profile,
    now: base.now + 10, removeDevices: [fromHex(created.devices[0].id)]});
  check(fresh.devices.length === 1 && fresh.devices[0].id !== created.devices[0].id && fresh.id === created.id,
    'DC renewal enrolls a fresh device and prunes stale setup authority');
  check(content(fresh.profile)[3] === content(created.profile)[3] + 1 &&
    content(fresh.profile)[5] === content(created.profile)[5] + 1 &&
    equal(content(fresh.profile)[6], new Uint8Array(await crypto.subtle.digest('SHA-256', decode(decode(created.profile)[4])[0]))),
    'DC revocation advances generation and preserves the revision chain');
  const full = decode(created.profile), template = decode(decode(full[3][0])[0]);
  // One capacity fixture, rather than publishing every intermediate device count.
  for(let count = 1; count < 128; count++) {
    const device = await diem.deviceKeys.generate();
    const key = bytes(encode({0: 'Diem/key', 1: 3, 2: 2, 3: 2, 4: device.publicKey}));
    const message = bytes(encode({...template, 4: key}));
    full[3].push(bytes(encode({0: message, 1: await alice.sign('identity', message)})));
  }
  const fullProfile = encode(full);
  await publicInfo(fullProfile);
  const atCapacity = await diem.dcSetup({...input, profile: fullProfile, device: freshDevice,
    now: base.now + 10, removeDevices: [fromHex(created.devices[0].id)]});
  check(atCapacity.devices.length === 128 && atCapacity.devices.some(device => device.current) &&
    !atCapacity.devices.some(device => device.id === created.devices[0].id), 'DC renewal prunes before adding at 128 devices');
  check(content(atCapacity.profile)[3] === 2 && content(atCapacity.profile)[5] === 2 &&
    equal(content(atCapacity.profile)[6], content(fresh.profile)[6]), 'Capacity renewal preserves generation and revision chain');
  await publicInfo(atCapacity.profile, base.now + 10);
  const freshID = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(encode({0: 'Diem/key', 1: 3, 2: 2, 3: 2, 4: freshDevice.publicKey}))));
  await rejectsWith(() => diem.dcSetup({...input, profile: fullProfile, device: freshDevice,
    removeDevices: [freshID]}), 'identityMismatch');
  await rejectsWith(() => diem.dcSetup({...input, profile: fullProfile, device: freshDevice}), 'invalidEncoding');
  check(equal(encode(fields(renewed.profile)), dcData), 'DC fields survive renewal');
  check(renewed.expiresAt === base.now + (91 + 45) * 86400, 'Chosen DC profile lifetime');
  check(renewed.devices[0].expiresAt === base.now + (91 + 120) * 86400, 'Chosen DC certificate lifetime');
  for(const lifetimes of [
    {profileLifetime: 0}, {deviceLifetime: 0}, {profileLifetime: -1}, {deviceLifetime: 1.5},
    {profileLifetime: 121 * 86400, deviceLifetime: 120 * 86400},
    {deviceLifetime: Number.MAX_SAFE_INTEGER}
  ]) await rejects(() => diem.dcSetup({...input, ...lifetimes}));
  await rejects(() => diem.dcSetup({...input, profile: first.profile}));
  await rejects(() => diem.dcSetup({...input, data: encode(fields(first.profile))}));
  await rejects(() => diem.dcSetup({...input, data: encode({...fields(created.profile), 10: null})}));
  // Callers author only domains and application fields; the old integer layout is refused.
  await rejects(() => diem.dcSetup({...input, data: encode({9: ['dc.example.org'], 16: 5, 20: 'transport-public-key', 21: 1})}));
  await rejects(() => diem.dcSetup({...input, data: new Array(10)}));
  await rejects(() => diem.dcSetup({...input, now: 1.5}));
  const wrongSigner = await backend();
  await rejects(() => diem.dcSetup({...input, seed: wrongSigner.seed, profile: created.profile}));
  const corrupt = [...created.profile]; corrupt[corrupt.length - 1] ^= 1;
  await rejects(() => diem.dcSetup({...input, profile: corrupt}));
}
