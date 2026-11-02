import assert from 'node:assert/strict';
import {test} from 'node:test';
import {deviceLink} from '../device-links.js';

test('approvals isolate seeds and clear bridge inputs on success and worker failures', async() => {
  const original = globalThis.Worker;
  const seed = new Uint8Array(32).fill(123);
  const instances = [];
  let failure;
  globalThis.Worker = class {
    constructor() {
      if(failure === 'create') throw new Error('injected');
      instances.push(this);
    }
    terminate() { this.ended = true; }
    postMessage(message) {
      this.input = message.input;
      if(failure === 'post') throw new Error('injected');
      queueMicrotask(() => {
        if(failure === 'error') this.onerror({message: 'injected'});
        else if(failure === 'clone') this.onmessageerror();
        else this.onmessage({data: {id: message.id, ...(failure === 'operation' ? {error: 'injected'} : {result: [1]})}});
      });
    }
  };
  const exports = new Proxy({}, {get() { throw new Error('Main WASM must not handle approval'); }});
  try {
    const links = deviceLink(exports, new URL('../dist/diem.wasm', import.meta.url));
    for(failure of [undefined, 'operation', 'error', 'clone', 'post', 'create']) {
      const action = () => links.respond({seed, code: 'code', domain: 'example.org', request: [], profile: []});
      if(failure) await assert.rejects(action);
      else assert.deepEqual(await action(), new Uint8Array([1]));
      assert.ok(seed.every(byte => byte === 123));
      for(const worker of instances) {
        assert.equal(worker.ended, true);
        assert.ok(worker.input.seed.every(byte => byte === 0));
      }
    }
  } finally { globalThis.Worker = original; seed.fill(0); }
});

test('link opening clears its source seed and ends its worker on success and conversion failure', async() => {
  const original = globalThis.Worker;
  let source, failure, worker;
  globalThis.Worker = class {
    constructor() { worker = this; }
    terminate() { this.ended = true; }
    postMessage(message) {
      const result = message.operation === 'begin' ? {request: [], parameter: 'code'} :
        {profile: failure ? Symbol() : [1], seed: source = new Uint8Array(32).fill(123)};
      queueMicrotask(() => this.onmessage({data: {id: message.id, result}}));
    }
  };
  try {
    const links = deviceLink({}, new URL('../dist/diem.wasm', import.meta.url));
    for(failure of [false, true]) {
      const {session} = await links.begin('Desktop');
      const action = () => links.open(session, [], new Uint8Array(32));
      if(failure) await assert.rejects(action);
      else {
        const opened = await action();
        try { assert.ok(opened.seed.every(byte => byte === 123)); } finally { opened.seed.fill(0); }
      }
      assert.ok(source.every(byte => byte === 0));
      assert.equal(worker.ended, true);
      await assert.rejects(() => links.open(session, [], new Uint8Array(32)));
    }
  } finally { globalThis.Worker = original; source?.fill(0); }
});
