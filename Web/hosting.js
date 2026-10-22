import {sha256} from '@noble/hashes/sha2.js';

const cap = 262_144;
const failure = type => ({type});
const cancelled = () => failure('cancelled');
function signalOption(signal) {
  if(signal !== undefined && !(signal instanceof AbortSignal)) throw new TypeError('Invalid signal');
}
function domainName(domain) {
  if(typeof domain !== 'string' || domain.length > 253 || !domain.includes('.') ||
    domain.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new TypeError('Invalid hosting domain');
  }
}
function labelList(labels) {
  if(!Array.isArray(labels) || labels.length > 16 || labels.some(label => typeof label !== 'string' || label.length > 253)) {
    throw new TypeError('Invalid hosting labels');
  }
}
function abortable(action, signal) {
  if(signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener('abort', abort, {once: true});
    Promise.resolve().then(action).then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

export function fetchTransport({signal, timeout = 15_000} = {}) {
  signalOption(signal);
  if(!Number.isSafeInteger(timeout) || timeout <= 0 || timeout > 2_147_483_647) throw new TypeError('Invalid timeout');
  return async request => {
    const controller = new AbortController();
    const abort = () => controller.abort(signal.reason);
    if(signal?.aborted) abort();
    else signal?.addEventListener('abort', abort, {once: true});
    const timer = setTimeout(() => controller.abort(new DOMException('Hosting request timed out', 'TimeoutError')), timeout);
    let reader;
    try {
      return await abortable(async() => {
        const response = await fetch(request.url, {method: request.method, headers: request.headers,
          body: request.body === null ? null : new Uint8Array(request.body), signal: controller.signal,
          redirect: 'error', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer'});
        const length = response.headers.get('content-length');
        if(length !== null && Number(length) > cap) throw failure('tooLarge');
        const chunks = [];
        let size = 0;
        reader = response.body?.getReader();
        if(reader) while(true) {
          const {done, value} = await reader.read();
          if(done) break;
          size += value.length;
          if(size > cap) throw failure('tooLarge');
          chunks.push(value);
        }
        const body = new Uint8Array(size);
        let offset = 0;
        for(const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
        return {status: response.status, headers: Object.fromEntries(response.headers), body};
      }, controller.signal);
    } finally {
      controller.abort();
      reader?.cancel().catch(() => {});
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
    }
  };
}

export function hosting(exports, bytes) {
  function callbacks(transport = fetchTransport(), solver) {
    if(typeof transport !== 'function' || solver !== undefined && typeof solver !== 'function') {
      throw new TypeError('Invalid hosting callback');
    }
    return {
      async http(method, url, names, values, body) {
        const response = await transport({method, url, headers: Object.fromEntries(names.map((name, i) => [name, values[i]])), body});
        if(!response || !Number.isInteger(response.status) || response.status < 100 || response.status > 599 ||
          !response.headers || typeof response.headers !== 'object' || Array.isArray(response.headers) ||
          Object.values(response.headers).some(value => typeof value !== 'string')) throw failure('invalidResponse');
        if(response.body?.length > cap) throw failure('tooLarge');
        let responseBody;
        try { responseBody = bytes(response.body, 'HTTP response', cap); }
        catch { throw failure('invalidResponse'); }
        return {status: response.status, names: Object.keys(response.headers), values: Object.values(response.headers), body: responseBody};
      },
      async solve(label, input, requiredBits) {
        const nonce = await solver({label, input, requiredBits});
        // Native code verifies the nonce's length and hash before publication.
        try { return bytes(nonce, 'solver nonce', 64); }
        catch { throw failure('invalidProof'); }
      }
    };
  }
  return {
    fetchTransport,
    async policy(domain, transport) {
      domainName(domain);
      return exports.hostingPolicy(domain, callbacks(transport));
    },
    async plan(domain, labels, identity, transport) {
      domainName(domain); labelList(labels);
      if(typeof identity !== 'string' || !/^[0-9a-f]{64}$/.test(identity)) throw new TypeError('Invalid hosting identity');
      return exports.hostingPlan(domain, labels, Array.from(identity.matchAll(/../g), ([hex]) => parseInt(hex, 16)), callbacks(transport));
    },
    async solve(puzzle, {signal, start = 0, stride = 1, onProgress} = {}) {
      signalOption(signal);
      if(!puzzle || typeof puzzle.label !== 'string' || puzzle.label.length > 63 ||
        !Number.isInteger(puzzle.requiredBits) || puzzle.requiredBits < 0 || puzzle.requiredBits > 64 ||
        !Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(stride) || stride <= 0 ||
        onProgress !== undefined && typeof onProgress !== 'function') throw new TypeError('Invalid hosting puzzle');
      const input = bytes(puzzle.input, 'puzzle', 1024);
      const base = sha256.create().update(new Uint8Array(input));
      const nonce = new Uint8Array(8), view = new DataView(nonce.buffer);
      let counter = BigInt(start), attempts = 0, lastProgress = performance.now();
      const step = BigInt(stride), maximum = (1n << 64n) - 1n;
      try {
        while(counter <= maximum) {
          if(signal?.aborted) throw cancelled();
          for(let batch = 0; batch < 4096 && counter <= maximum; batch++, counter += step) {
            view.setBigUint64(0, counter);
            const hash = base.clone().update(nonce).digest();
            let bits = 0;
            for(const byte of hash) { bits += Math.clz32(byte) - 24; if(byte) break; }
            attempts++;
            if(bits >= puzzle.requiredBits) {
              onProgress?.(attempts);
              if(signal?.aborted) throw cancelled();
              return Array.from(nonce);
            }
          }
          if(performance.now() - lastProgress >= 100) {
            onProgress?.(attempts); lastProgress = performance.now();
          }
          // Timer tasks let AbortSignal events run even when scheduler continuations
          // would repeatedly outrank timers in Chromium.
          await new Promise(resolve => setTimeout(resolve, 0));
        }
        throw failure('unsolvable');
      } finally { base.destroy(); }
    },
    async publish(domain, profile, {via, proofs = {}, solver, transport} = {}) {
      domainName(domain);
      if(via !== undefined) labelList([via]);
      if(!proofs || typeof proofs !== 'object' || Array.isArray(proofs)) throw new TypeError('Invalid proofs');
      const labels = Object.keys(proofs);
      labelList(labels);
      return exports.hostingPublish(domain, bytes(profile, 'profile', cap), via ?? null,
        labels.map(label => ({label, nonce: bytes(proofs[label], 'proof', 64)})),
        solver !== undefined, callbacks(transport, solver));
    }
  };
}
