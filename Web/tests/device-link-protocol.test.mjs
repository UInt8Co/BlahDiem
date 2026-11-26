// Blah's protocol on Diem's link machinery (Diem tests the machinery itself): Blah's
// inputs are validated and its seed and metadata are wiped wherever they pass.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {deviceLink} from '../.build-embedded/checkouts/diem/Web/device-links.js';
import {blahLinkProtocol} from '../device-link-protocol.js';

const wasm = new URL('../dist/diem.wasm', import.meta.url);

test('approvals check metadata and wipe the seed and metadata on success and failure', async() => {
  const original = globalThis.Worker;
  const seed = new Uint8Array(32).fill(123), metadata = new Uint8Array([7, 7, 7]);
  const instances = [];
  let failure;
  globalThis.Worker = class {
    constructor() { instances.push(this); }
    terminate() { this.ended = true; }
    postMessage(message) {
      this.input = message.input;
      queueMicrotask(() => this.onmessage({data: {id: message.id, ...(failure ? {error: 'injected'} : {result: [1]})}}));
    }
  };
  const exports = new Proxy({}, {get() { throw new Error('Main WASM must not handle approval'); }});
  try {
    const links = deviceLink(exports, wasm, blahLinkProtocol);
    const input = {seed, metadata, code: 'code', domain: 'example.org', request: [], profile: []};
    await assert.rejects(() => links.respond({...input, seed: undefined}), TypeError);
    await assert.rejects(() => links.respond({...input, metadata: new Uint8Array(16385)}), TypeError);
    assert.equal(instances.length, 0);
    for(failure of [false, true]) {
      const action = () => links.respond(input);
      if(failure) await assert.rejects(action);
      else assert.deepEqual(await action(), new Uint8Array([1]));
      assert.ok(seed.every(byte => byte === 123) && metadata.every(byte => byte === 7));
      for(const worker of instances) {
        assert.equal(worker.ended, true);
        assert.ok(worker.input.seed.every(byte => byte === 0) && worker.input.metadata.every(byte => byte === 0));
      }
    }
  } finally { globalThis.Worker = original; }
});

test('opening requires the expected DC and wipes the source seed and metadata', async() => {
  const original = globalThis.Worker;
  let seed, metadata, opened;
  globalThis.Worker = class {
    terminate() { this.ended = true; }
    postMessage(message) {
      if(message.operation === 'open') opened = message;
      const result = message.operation === 'begin' ? {request: [], parameter: 'code'} :
        {profile: [1], domain: 'example.org', seed: seed = new Uint8Array(32).fill(123), metadata: metadata = [9, 9]};
      queueMicrotask(() => this.onmessage({data: {id: message.id, result}}));
    }
  };
  try {
    const links = deviceLink({}, wasm, blahLinkProtocol);
    const rejected = await links.begin('Desktop');
    await assert.rejects(() => links.open(rejected.session, [], new Uint8Array(31)), TypeError);
    await assert.rejects(() => links.open(rejected.session, [], new Uint8Array(32)));
    const {session} = await links.begin('Desktop');
    const result = await links.open(session, [], new Uint8Array(32).fill(5));
    assert.deepEqual(opened.expectedDC, Array(32).fill(5));
    assert.ok(result.seed.every(byte => byte === 123));
    assert.deepEqual(result.metadata, new Uint8Array([9, 9]));
    assert.ok(seed.every(byte => byte === 0) && metadata.every(byte => byte === 0));
    result.seed.fill(0);
  } finally { globalThis.Worker = original; }
});
