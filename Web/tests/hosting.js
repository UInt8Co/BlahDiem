import {encode, decode} from './cbor.js';

const utf8 = text => new TextEncoder().encode(text);
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const base64 = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const json = (value, status = 200, headers = {}) => ({status, headers, body: utf8(JSON.stringify(value))});
const policy = {domain: 'id.example', labelPattern: '[a-z0-9-]+', maxClaimsPerIdentity: 3,
  maxUpdatesPerIdentityPerHour: 12, claimGraceAfterExpiry: 2_592_000,
  proofOfWork: {algorithm: 'sha256-leading-zero-bits-v1', baseBits: 4, bitsPerShorterCharacter: 0, referenceLength: 8}};
const fields = profile => decode(decode(decode(profile)[4])[0]);
const puzzle = (label, identity, bits = 4) => ({label, requiredBits: bits,
  input: [...utf8(`diem-profile-hosting-pow-v1\0id.example\0${label}\0`), ...identity]});
async function solved(work, nonce) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([...work.input, ...nonce])));
  let bits = 0;
  for(const byte of digest) { bits += Math.clz32(byte) - 24; if(byte) break; }
  return nonce.length >= 1 && nonce.length <= 64 && bits >= work.requiredBits;
}

// Independent host wire implementation; no global fetch replacement.
function fakeHost() {
  const claims = new Map(), revisions = new Map(), requests = [];
  const host = {requests, limited: false, alwaysProof: false, omitBits: false, zeroBits: false};
  function problem(code, status, labels = []) {
    return json({type: 'urn:diem:profile-hosting:' + code, title: code, status, detail: 'Refused',
      labels: labels.map(label => ({label, reason: code,
        ...(code === 'proof-required' && !host.omitBits ? {requiredBits: 4} : {})}))}, status,
      status === 429 ? {'rEtRy-AfTeR': '37'} : {});
  }
  host.transport = async request => {
    requests.push(request);
    const url = new URL(request.url), label = url.hostname.slice(0, -'.id.example'.length);
    if(url.hostname === 'id.example') {
      if(url.pathname === '/.well-known/diem/hosting') return json(policy);
      const label = url.pathname.split('/').pop();
      return json({label, status: label === 'reserved' ? 'invalid' : claims.has(label) ? 'claimed' : 'available',
        ...(!host.omitBits ? {requiredBits: host.zeroBits ? 0 : 4} : {})});
    }
    if(request.method === 'GET') return claims.has(label) ? {status: 200, headers: {}, body: claims.get(label)} : json({}, 404);
    const content = fields(request.body), id = hex(content[2]), revision = BigInt(content[5]);
    const names = content[9].filter(name => name.endsWith('.id.example')).map(name => name.slice(0, -11));
    const published = () => ({status: 200, headers: {}, body: utf8(
      `{"identity":"${base64(content[2])}","revision":${revision},"domains":${JSON.stringify(names.map(name => name + '.id.example'))}}`)});
    if(!names.includes(label) && !(names.length === 0 && claims.has(label) && hex(fields(claims.get(label))[2]) === id)) {
      return problem('host-not-listed', 422);
    }
    const previous = revisions.get(id);
    if(previous) {
      if(hex(previous) === hex(request.body)) return published();
      if(BigInt(fields(previous)[5]) >= revision) return problem('stale-revision', 409);
    }
    const taken = names.filter(name => claims.has(name) && hex(fields(claims.get(name))[2]) !== id);
    if(taken.length) return problem('name-taken', 409, taken);
    const proofs = Object.fromEntries((request.headers['Diem-Hosting-Proof'] || '').split(', ').filter(Boolean).map(entry => {
      const [name, nonce] = entry.split('=');
      return [name, Array.from(atob(nonce.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0))];
    }));
    const missing = [];
    for(const name of names) {
      if(claims.has(name) && hex(fields(claims.get(name))[2]) === id) continue;
      if(!await solved(puzzle(name, content[2]), proofs[name] || [])) missing.push(name);
    }
    if(missing.length || host.alwaysProof) return problem('proof-required', 403, missing.length ? missing : names);
    if(host.limited) return problem('rate-limited', 429);
    for(const [name, profile] of claims) if(hex(fields(profile)[2]) === id) claims.delete(name);
    for(const name of names) claims.set(name, request.body);
    revisions.set(id, request.body);
    return published();
  };
  return host;
}

export async function exerciseHosting({diem, check, base, alice, bob, first}) {
  const hosting = diem.hosting, host = fakeHost(), transport = host.transport;
  const reject = async(action, expected) => {
    try { await action(); } catch(error) {
      check(typeof expected === 'function' ? expected(error) : error?.type === expected,
        `Hosting rejection: expected ${expected}, got ${error?.type || error?.message || error}`);
      return error;
    }
    throw new Error(`Expected hosting rejection ${expected}`);
  };
  check((await hosting.policy('id.example', transport)).proofOfWork.baseBits === 4, 'Hosting policy');
  const plan = await hosting.plan('id.example', ['BAD', 'reserved', 'alice'], first.id, transport);
  check(plan.map(name => name.status).join() === 'invalid,invalid,needsProof', 'Plan invalid and proof statuses');
  check(plan[0].requiredBits === null && plan[0].puzzle === null && plan[2].requiredBits === 4, 'Nullable plan fields');
  check(hex(plan[2].puzzle.input) === hex(puzzle('alice', fields(first.profile)[2]).input), 'Native puzzle identity binding');
  host.zeroBits = true;
  const free = (await hosting.plan('id.example', ['free'], first.id, transport))[0];
  check(free.requiredBits === 0 && free.puzzle === null, 'Zero-bit plan');
  host.zeroBits = false;
  host.omitBits = true;
  check((await hosting.plan('id.example', ['fallback'], first.id, transport))[0].requiredBits === 4, 'Policy difficulty fallback');
  host.omitBits = false;

  const golden = puzzle('alice', Array.from({length: 32}, (_, i) => i + 1), 12);
  let progress = 0;
  const nonce = await hosting.solve(golden, {onProgress: attempts => { progress = attempts; }});
  check(hex(nonce) === '0000000000002237' && progress === 8760 && await solved(golden, nonce), 'Golden nonce and independent WebCrypto verification');
  check(hex(await hosting.solve(golden, {start: 8759, stride: 3})) === hex(nonce), 'Solver start and stride');
  await reject(() => hosting.solve({...golden, requiredBits: 65}), error => error instanceof TypeError);
  await reject(() => hosting.plan('id.example', ['alice'], first.id.toUpperCase(), transport), error => error instanceof TypeError);

  const signed = await diem.identityOperation({...base, operation: 'domains', profile: first.profile,
    domains: [base.domain, 'alice.id.example']}, alice);
  const proof = await hosting.solve(plan[2].puzzle);
  const published = await hosting.publish('id.example', signed.profile, {proofs: {alice: proof}, transport});
  const verified = await diem.verifyProfile(signed.profile, base.now, alice);
  check(published.identity === first.id && published.revision === verified.revision && published.domains.join() === 'alice.id.example', 'Create → domains → publish');
  const puts = () => host.requests.filter(request => request.method === 'PUT');
  check(hex(puts()[0].body) === hex(signed.profile) && puts()[0].headers['Diem-Hosting-Proof'] === `alice=${base64(proof)}`, 'Exact signed bytes and proof header');
  await hosting.publish('id.example', signed.profile, {transport});
  check((await hosting.plan('id.example', ['alice'], first.id, transport))[0].status === 'held', 'Held hint fetched from profile');
  check((await hosting.plan('id.example', ['alice'], '00'.repeat(32), transport))[0].status === 'taken', 'Taken hint fetched from profile');
  const other = await diem.identityOperation({...base, domain: 'alice.id.example'}, bob);
  const taken = await reject(() => hosting.publish('id.example', other.profile, {transport}), 'hostingProblem');
  check(taken.code === 'name-taken' && taken.status === 409 && taken.detail === 'Refused' && taken.retryAfter === null &&
    taken.labels[0].label === 'alice' && taken.labels[0].reason === 'name-taken' && taken.labels[0].requiredBits === null, 'Problem object shape');

  const next = await diem.identityOperation({...base, operation: 'domains', profile: signed.profile,
    domains: [base.domain, 'alice.id.example', 'bob.id.example']}, alice);
  const before = puts().length, solvedLabels = [];
  await hosting.publish('id.example', next.profile, {transport, solver: async work => {
    solvedLabels.push(work.label); return hosting.solve(work);
  }});
  check(puts().length === before + 2 && solvedLabels.join() === 'bob', 'Retry exactly the missing proof once');
  const badHost = fakeHost();
  await reject(() => hosting.publish('id.example', signed.profile, {transport: badHost.transport, solver: async() => []}), 'invalidProof');
  check(badHost.requests.filter(request => request.method === 'PUT').length === 1, 'Bad solver nonce never sent');
  await reject(() => hosting.publish('id.example', signed.profile, {transport: badHost.transport, solver: async() => [256]}), 'invalidProof');
  await reject(() => hosting.publish('id.example', signed.profile, {transport: badHost.transport, proofs: {alice: []}}), 'invalidProof');
  badHost.alwaysProof = true;
  const refusal = await reject(() => hosting.publish('id.example', signed.profile,
    {transport: badHost.transport, solver: work => hosting.solve(work)}), 'hostingProblem');
  check(refusal.code === 'proof-required' && refusal.labels[0].requiredBits === 4, 'One retry limit and difficulty error field');
  badHost.alwaysProof = false; badHost.limited = true;
  const limited = await reject(() => hosting.publish('id.example', signed.profile,
    {transport: badHost.transport, solver: work => hosting.solve(work)}), 'hostingProblem');
  check(limited.code === 'rate-limited' && limited.status === 429 && limited.retryAfter === 37 && limited.labels.length === 0, 'Retry-After seconds');

  const marker = {message: 'callback rejection'};
  await reject(() => hosting.policy('id.example', async() => { throw marker; }), error => error === marker);
  await reject(() => hosting.publish('id.example', signed.profile,
    {transport: fakeHost().transport, solver: async() => { throw marker; }}), error => error === marker);
  await reject(() => hosting.policy('id.example', async() => json({...policy, domain: 'wrong.example'})), 'domainMismatch');
  await reject(() => hosting.policy('id.example', async() => json({...policy, proofOfWork: {...policy.proofOfWork, algorithm: 'other'}})), 'unsupportedAlgorithm');
  await reject(() => hosting.policy('id.example', async() => ({status: 200, headers: {}, body: utf8('{')})), 'invalidResponse');
  await reject(() => hosting.policy('id.example', async() => ({status: 200, headers: {}, body: [256]})), 'invalidResponse');
  await reject(() => hosting.publish('id.example', [0], {transport}), 'invalidResponse');
  const status = await reject(() => hosting.policy('id.example', async() => ({status: 302, headers: {}, body: []})), 'unexpectedStatus');
  check(status.status === 302, 'Unexpected status field');
  const unknown = await reject(() => hosting.policy('id.example', async() => json({type: 'urn:diem:profile-hosting:future',
    title: 'Future', status: 503, detail: 'Later'}, 503)), 'hostingProblem');
  check(unknown.code === 'future' && unknown.labels.length === 0, 'Unknown wire code preserved');
  await reject(() => hosting.publish('id.example', first.profile, {transport}), 'noHostedName');
  await reject(() => hosting.publish('id.example', signed.profile, {via: 'outside', transport}), 'hostNotListed');
  await reject(() => hosting.publish('id.example', signed.profile, {transport: async() => json({identity: 'wrong', revision: 2, domains: []})}), 'publishedMismatch');

  const released = await diem.identityOperation({...base, operation: 'domains', profile: next.profile,
    domains: [base.domain]}, alice);
  const release = await hosting.publish('id.example', released.profile, {via: 'alice', transport});
  check(release.domains.length === 0, 'Release through a formerly held name');
  const repeatedRelease = await reject(() => hosting.publish('id.example', released.profile, {via: 'alice', transport}), 'hostingProblem');
  check(repeatedRelease.code === 'host-not-listed', 'Completed full release requires reconciliation');

  // Unknown application kind and >2^53 revision: publication is a Diem operation.
  const envelope = decode(signed.profile), message = fields(signed.profile);
  message[5] = 9007199254740993n;
  message[16] = 999;
  const encoded = encode(message);
  envelope[4] = new Uint8Array(encode({0: new Uint8Array(encoded), 1: await alice.sign('device', encoded)}));
  const generic = encode(envelope);
  const precise = await hosting.publish('id.example', generic, {transport, solver: work => hosting.solve(work)});
  check(precise.revision === '9007199254740993', 'Kind-independent publication and exact revision');

  const controller = new AbortController();
  setTimeout(() => controller.abort(), 0);
  await reject(() => hosting.solve({...golden, requiredBits: 64}, {signal: controller.signal}), 'cancelled');
  const solverAbort = new AbortController();
  let settled = false;
  const pending = hosting.publish('id.example', signed.profile, {transport: fakeHost().transport,
    solver: work => { setTimeout(() => solverAbort.abort(), 0); return hosting.solve({...work, requiredBits: 64}, {signal: solverAbort.signal}); }});
  await reject(() => pending.finally(() => { settled = true; }), 'cancelled');
  check(settled, 'Swift publish task settles after solver cancellation');

  const local = path => new URL('/hosting/' + path, location.href).href;
  const request = path => ({method: 'GET', url: local(path), headers: {}, body: null});
  const fetcher = hosting.fetchTransport();
  await reject(() => fetcher(request('redirect')), error => error instanceof TypeError);
  for(const path of ['large', 'stream']) await reject(() => fetcher(request(path)), 'tooLarge');
  for(const path of ['hang', 'body-hang']) {
    await reject(() => hosting.fetchTransport({timeout: 20})(request(path)), error => error.name === 'TimeoutError');
  }
  const fetchAbort = new AbortController();
  const cancelTransport = hosting.fetchTransport({signal: fetchAbort.signal});
  const cancelledPolicy = hosting.policy('id.example', req => cancelTransport({...req, url: local('body-hang')}));
  setTimeout(() => fetchAbort.abort(), 10);
  await reject(() => cancelledPolicy, error => error.name === 'AbortError');
  check((await hosting.policy('id.example', transport)).domain === 'id.example', 'Runtime works after aborted Swift HTTP continuation');
  const privacy = JSON.parse(new TextDecoder().decode((await fetcher(request('privacy'))).body));
  check(!privacy.cookie && !privacy.referer, 'Fetch omits credentials and referrer');

  for(const kind of ['bot', 'channel', 'stickerSet']) {
    const created = await diem.identityOperation({...base, kind}, alice);
    const domains = kind === 'stickerSet' ? ['kind.id.example'] : [base.domain, 'kind.id.example'];
    const changed = await diem.identityOperation({...base, kind, operation: 'domains', profile: created.profile, domains}, alice);
    check((await diem.verifyProfile(changed.profile, base.now, alice)).kind === kind, 'Domains preserve ' + kind);
    await hosting.publish('id.example', changed.profile, {transport: fakeHost().transport, solver: work => hosting.solve(work)});
  }
}
