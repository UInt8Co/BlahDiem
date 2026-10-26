import {createDiem} from '../dist/diem.js';
import {encode, decode} from './cbor.js';
import {installFixtureCrypto} from './device-link-fixture-crypto.js';

const check = (condition, message) => { if(!condition) throw new Error(message); };
const equal = (actual, expected, message) => check(JSON.stringify(Array.from(actual)) === JSON.stringify(Array.from(expected)), message);
const bytes = value => new Uint8Array(value);
const base64 = value => btoa(String.fromCharCode(...value));
const base64url = value => base64(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function rejects(action, message) {
  try { await action(); } catch { return; }
  throw new Error(`Expected rejection: ${message}`);
}
const signingKey = async seed => {
  const pkcs8 = bytes([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, ...seed]);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  const publicKey = await crypto.subtle.importKey('jwk', {kty: 'OKP', crv: 'Ed25519', x: jwk.x}, 'Ed25519', true, ['verify']);
  return {privateKey, publicKey, contents: {privateKey: base64(pkcs8), publicKey: base64(new Uint8Array(await crypto.subtle.exportKey('raw', publicKey)))}};
};

// Inject the fixed test inputs in either the current worker or a newly spawned worker.
// This supports both hosting choices while keeping the public N session opaque.
async function nativeRecipientSession(diem, vector) {
  const restoreCrypto = await installFixtureCrypto(vector);
  const Worker = globalThis.Worker;
  if(Worker) globalThis.Worker = class extends Worker {
    constructor(target, options) {
      const bootstrap = new URL('./device-link-fixture-worker.js', import.meta.url);
      bootstrap.searchParams.set('target', String(target));
      super(bootstrap, options);
    }
  };
  try {
    const result = await diem.deviceLink.begin('Interop desktop');
    equal(result.request, vector.request, 'Browser N canonical request differs from fixed native fixture');
    check(result.parameter === vector.parameter, 'Browser N code differs from fixed native fixture');
    return result;
  } finally { restoreCrypto(); if(Worker) globalThis.Worker = Worker; }
}

export async function run() {
  const vector = await (await fetch(new URL('./device-link-native.json', import.meta.url))).json();
  const diem = await createDiem(new URL('../dist/diem.wasm', import.meta.url));
  const now = Date.now;
  Date.now = () => vector.now * 1000;
  try {
    const inspected = await diem.deviceLink.inspect(vector.parameter, bytes(vector.request));
    equal(inspected.device, decode(vector.request)[2], 'O inspects the exact device');
    equal(inspected.verifies, [1], 'O sees verification algorithms');
    check(inspected.label === 'Interop desktop', 'O sees requested label');
    for(const label of ['', 'é'.repeat(33), 'a'.repeat(65)]) {
      await rejects(() => diem.deviceLink.begin(label), 'label UTF-8 bounds');
    }
    for(const label of ['a', 'a'.repeat(64), 'é'.repeat(32)]) {
      const started = await diem.deviceLink.begin(label);
      check((await diem.deviceLink.inspect(started.parameter, started.request)).label === label, 'Valid label boundary');
      started.session.destroy?.();
    }
    for(const parameter of ['', 'A', vector.parameter + '=', ' ' + vector.parameter, vector.parameter + '\n', '+' + vector.parameter, '/' + vector.parameter]) {
      await rejects(() => diem.deviceLink.inspect(parameter, bytes(vector.request)), 'malformed QR text');
    }
    for(let index = 0; index < 32; index++) {
      const code = decode(vector.code); code[2][index] ^= 1;
      await rejects(() => diem.deviceLink.inspect(base64url(encode(code)), bytes(vector.request)), `digest byte ${index}`);
    }
    const substituted = await diem.deviceLink.begin('Relay substitution');
    await rejects(() => diem.deviceLink.inspect(vector.parameter, substituted.request), 'relay swaps N request');
    substituted.session.destroy?.();
    for(const [key, value] of [[0, 18], [1, 2], [4, ''], [5, []], [5, [1, 1]], [99, new Uint8Array(4096)]]) {
      const request = decode(vector.request); request[key] = value;
      const encoding = bytes(encode(request));
      const code = decode(vector.code); code[2] = new Uint8Array(await crypto.subtle.digest('SHA-256', encoding));
      await rejects(() => diem.deviceLink.inspect(base64url(encode(code)), encoding), 'invalid request even with matching digest');
    }
    const future = decode(vector.request); future[99] = 'future';
    const extended = bytes(encode(future));
    const futureCode = decode(vector.code); futureCode[2] = new Uint8Array(await crypto.subtle.digest('SHA-256', extended));
    check((await diem.deviceLink.inspect(base64url(encode(futureCode)), extended)).label === 'Interop desktop', 'Unknown request keys accepted');

    for(const [response, transfers] of [[vector.response, true], [vector.deviceOnlyResponse, false]]) {
      const begun = await nativeRecipientSession(diem, vector);
      try {
        const opened = await diem.deviceLink.open(begun.session, bytes(response), bytes(vector.dc));
        equal(opened.profile, vector.profile, 'N opens exact natively sealed profile');
        check(opened.domain === vector.domain && opened.identityKey === transfers, 'Native grant authority');
        if(transfers) equal(opened.metadata, vector.metadata, 'Opaque metadata preserved');
        else check(opened.metadata === undefined, 'Device-only grant has no metadata');
        check(opened.keyFileContents.length > 0, 'N receives portable custody contents');
        const contents = decode(opened.keyFileContents);
        check(contents[0] === 15, 'Custody is KeyFileContents');
        equal(contents[2], vector.profile, 'Custody carries certified profile');
        check(contents[3].length === (transfers ? 2 : 1), 'Custody contains exactly granted keys');
        const custody = await diem.keyFiles.create('N local password');
        let restored;
        try {
          const file = await custody.seal(opened.keyFileContents);
          opened.keyFileContents.fill(0);
          restored = await diem.keyFiles.unlock(file, 'N local password');
          check(restored.contents.domain === vector.domain, 'Custody installs the grant domain');
          check(!!restored.contents.device && !!restored.contents.identity === transfers, 'Password-sealed custody preserves authority');
          equal(new Uint8Array(atob(restored.contents.profile).split('').map(c => c.charCodeAt(0))), vector.profile, 'Password-sealed custody preserves the published profile');
        } finally { restored?.session.destroy(); custody.destroy(); }
      } finally { begun.session.destroy?.(); }
    }
    for(const test of ['ciphertext', 'DC', 'oversized', 'different recipient']) {
      const begun = test === 'different recipient' ? await diem.deviceLink.begin('Other N') : await nativeRecipientSession(diem, vector);
      const response = test === 'oversized' ? new Uint8Array(65537) : bytes(vector.response);
      const dc = bytes(vector.dc);
      if(test === 'ciphertext') response[response.length - 1] ^= 1;
      if(test === 'DC') dc[0] ^= 1;
      try {
        await rejects(() => diem.deviceLink.open(begun.session, response, dc), test);
        await rejects(() => diem.deviceLink.open(begun.session, bytes(vector.response), bytes(vector.dc)), 'Failure is fatal for the session');
      }
      finally { begun.session.destroy?.(); }
    }

    const identity = await signingKey(vector.identitySecret), signer = await signingKey(vector.signerSecret);
    const custody = await diem.keyFiles.create('x');
    let unlocked;
    try {
      const file = await custody.seal({domain: vector.domain, profile: base64(vector.profile),
        identity: identity.contents, device: signer.contents});
      unlocked = await diem.keyFiles.unlock(file, 'x');
      const input = {parameter: vector.parameter, request: bytes(vector.request), profile: bytes(vector.profile), domain: vector.domain};
      const response = await unlocked.session.respondToDeviceLink({...input, transferIdentity: true, metadata: bytes(vector.metadata)});
      const deviceOnlyResponse = await unlocked.session.respondToDeviceLink({...input, transferIdentity: false});
      const swapped = await diem.deviceLink.begin('Attacker');
      try {
        await rejects(() => unlocked.session.respondToDeviceLink({...input, request: swapped.request, transferIdentity: true}), 'O must check request digest before responding');
      } finally { swapped.session.destroy?.(); }
      await rejects(() => unlocked.session.respondToDeviceLink({...input, transferIdentity: false, metadata: bytes([1])}), 'metadata needs identity authority');
      await rejects(() => unlocked.session.respondToDeviceLink({...input, transferIdentity: true, metadata: new Uint8Array(16385)}), 'metadata bounds');
      return {realm: typeof document === 'undefined' ? 'worker' : 'window', response: Array.from(response), deviceOnlyResponse: Array.from(deviceOnlyResponse)};
    } finally { unlocked?.session.destroy(); custody.destroy(); }
  } finally { Date.now = now; }
}
