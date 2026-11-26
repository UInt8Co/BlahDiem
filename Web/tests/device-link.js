import {createDiem} from '../dist/diem.js';
import {decode} from './cbor.js';
import {installFixtureCrypto} from './device-link-fixture-crypto.js';
import {verify} from './signers.js';

const check = (condition, message) => { if(!condition) throw new Error(message); };
const equal = (actual, expected, message) => check(JSON.stringify(Array.from(actual)) === JSON.stringify(Array.from(expected)), message);
const bytes = value => new Uint8Array(value);
async function rejects(action, message) {
  try { await action(); } catch { return; }
  throw new Error(`Expected rejection: ${message}`);
}
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
    equal(inspected.verifies, [1, 2], 'O sees verification algorithms');
    check(inspected.label === 'Interop desktop', 'O sees requested label');
    for(const [response, transfers] of [[vector.response, true], [vector.deviceOnlyResponse, false]]) {
      const begun = await nativeRecipientSession(diem, vector);
      try {
        const opened = await diem.deviceLink.open(begun.session, bytes(response), bytes(vector.dc));
        equal(opened.profile, vector.profile, 'N opens exact natively sealed profile');
        check(opened.domain === vector.domain && !!opened.seed === transfers, 'Native grant authority');
        if(transfers) {
          equal(opened.metadata, vector.metadata, 'Opaque metadata preserved');
          equal(opened.seed, vector.entropy, 'Root entropy transferred');
        } else check(opened.metadata === undefined, 'Device-only grant has no metadata');
        check(opened.device.privateKey.extractable === false, 'No extractable device secret returned');
        equal(opened.device.publicKey, decode(decode(vector.request)[2])[4], 'Returned P-256 device matches request');
        const signature = new Uint8Array(await crypto.subtle.sign({name: 'ECDSA', hash: 'SHA-256'}, opened.device.privateKey, bytes([1, 2, 3])));
        check(signature.length === 64 && await verify(opened.device.publicKey, [1, 2, 3], signature), 'Native/browser P-256 signer agrees');
        for(const format of ['raw', 'pkcs8', 'jwk']) await rejects(() => crypto.subtle.exportKey(format, opened.device.privateKey), 'Device cannot export');
      } finally { begun.session.destroy?.(); }
    }
    // Blah's acceptance: the grant must be for a user homed at the DC this device expects.
    for(const dc of [bytes(vector.dc).map((v, i) => i ? v : v ^ 1), new Uint8Array(31)]) {
      const begun = await nativeRecipientSession(diem, vector);
      try {
        await rejects(() => diem.deviceLink.open(begun.session, bytes(vector.response), dc), 'unexpected DC');
        await rejects(() => diem.deviceLink.open(begun.session, bytes(vector.response), bytes(vector.dc)), 'Failure is fatal for the session');
      }
      finally { begun.session.destroy?.(); }
    }

    const input = {code: vector.parameter, request: bytes(vector.request), profile: bytes(vector.profile), domain: vector.domain};
    const response = await diem.deviceLink.respond({...input, seed: bytes(vector.entropy), metadata: bytes(vector.metadata)});
    const deviceOnlyResponse = await diem.deviceLink.respond(input);
    await rejects(() => diem.deviceLink.respond({...input, metadata: bytes([1])}), 'metadata requires seed transfer');
    await rejects(() => diem.deviceLink.respond({...input, seed: bytes(vector.entropy), metadata: new Uint8Array(16385)}), 'metadata bounds');
    await rejects(() => diem.deviceLink.respond({...input, seed: new Uint8Array(32)}), 'Seed must reproduce profile identity');
    return {realm: typeof document === 'undefined' ? 'worker' : 'window', response: Array.from(response), deviceOnlyResponse: Array.from(deviceOnlyResponse)};
  } finally { Date.now = now; }
}
