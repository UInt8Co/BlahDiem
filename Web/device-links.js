function bytes(value, limit) {
  if(!(value instanceof Uint8Array || Array.isArray(value)) || value.length > limit) {
    throw new TypeError('Invalid device-link bytes');
  }
  for(const byte of value) {
    if(!Number.isInteger(byte) || byte < 0 || byte > 255) throw new TypeError('Invalid device-link bytes');
  }
  return Array.from(value);
}

function parameter(value) {
  if(typeof value !== 'string' || value.length > 5462) throw new TypeError('Invalid device-link parameter');
  return value;
}

function linkResponseInput(input) {
  if(typeof input?.domain !== 'string' || input.domain.length > 253 ||
    (input.seed == null && input.metadata != null)) {
    throw new TypeError('Invalid device-link approval');
  }
  let seed, metadata, returned = false;
  try {
    const code = parameter(input.code), request = bytes(input.request, 4096), profile = bytes(input.profile, 65536);
    metadata = input.metadata == null ? null : bytes(input.metadata, 16384);
    seed = input.seed == null ? null : bytes(input.seed, 32);
    if(seed != null && seed.length !== 32) throw new TypeError('Invalid identity seed');
    const result = {code, request, profile, domain: input.domain, seed, metadata, now: Math.floor(Date.now() / 1000)};
    returned = true;
    return result;
  } finally { if(!returned) { seed?.fill(0); metadata?.fill(0); } }
}

export function deviceLink(exports, wasmURL) {
  const sessions = new WeakMap();
  return {
    async begin(label) {
      if(typeof label !== 'string' || new TextEncoder().encode(label).length < 1 ||
        new TextEncoder().encode(label).length > 64) throw new TypeError('Invalid device-link label');
      const worker = linkWorker(wasmURL);
      const {call, destroy} = worker;
      let opening = false;
      try {
        const result = await call('begin', {label});
        const session = Object.freeze({destroy});
        sessions.set(session, {
          async open(response, expectedDC) {
            let opened;
            try {
              if(opening) throw new Error('Device-link session ended');
              opening = true;
              const dc = bytes(expectedDC, 32);
              if(dc.length !== 32) throw new TypeError('Invalid DC identity');
              opened = await call('open', {response: bytes(response, 65536), expectedDC: dc, now: Math.floor(Date.now() / 1000)});
              return {...opened, profile: new Uint8Array(opened.profile),
                metadata: opened.metadata == null ? undefined : new Uint8Array(opened.metadata),
                seed: opened.seed == null ? undefined : new Uint8Array(opened.seed)};
            } finally {
              opened?.seed?.fill(0); opened?.metadata?.fill(0);
              destroy(); sessions.delete(session);
            }
          }
        });
        return {request: new Uint8Array(result.request), parameter: result.parameter, session};
      } catch(error) { destroy(); throw error; }
    },
    async open(session, response, expectedDC) {
      const state = sessions.get(session);
      if(!state) throw new Error('Device-link session ended');
      return state.open(response, expectedDC);
    },
    async respond(input) {
      const request = linkResponseInput(input);
      let worker;
      try {
        worker = linkWorker(wasmURL);
        return new Uint8Array(await worker.call('respond', {input: request}));
      } finally { request.seed?.fill(0); request.metadata?.fill(0); worker?.destroy(); }
    },
    async inspect(value, request) {
      const inspected = exports.inspectDeviceLink(parameter(value), bytes(request, 4096));
      return {...inspected, device: new Uint8Array(inspected.device)};
    }
  };
}

// Plaintext seeds use a disposable worker or isolated WASM heap, never the client's instance.
function linkWorker(wasmURL) {
  const url = new URL('./device-link-worker.js', import.meta.url);
  let objectURL, worker;
  const revoke = () => {
    if(objectURL) { URL.revokeObjectURL(objectURL); objectURL = undefined; }
  };
  try {
    if(typeof Worker === 'function') {
      if(globalThis.location && url.origin !== globalThis.location.origin) {
        objectURL = URL.createObjectURL(new Blob([`import ${JSON.stringify(url.href)};`], {type: 'text/javascript'}));
      }
      worker = new Worker(objectURL || url, {type: 'module'});
    } else worker = localLink(url);
  } catch(error) { revoke(); throw error; }
  const pending = new Map();
  let sequence = 0, closed = false;
  const destroy = () => {
    closed = true;
    revoke();
    worker.terminate();
    for(const {reject} of pending.values()) reject(new Error('Device-link session ended'));
    pending.clear();
  };
  worker.onmessage = ({data}) => {
    revoke();
    const call = pending.get(data.id);
    if(!call) { data.result?.seed?.fill(0); data.result?.metadata?.fill(0); return; }
    pending.delete(data.id);
    data.error ? call.reject(new Error(data.error)) : call.resolve(data.result);
  };
  worker.onerror = event => {
    for(const {reject} of pending.values()) reject(new Error(event.message || 'Device-link worker failed'));
    destroy();
  };
  worker.onmessageerror = destroy;
  return {
    destroy,
    call(operation, input) {
      return new Promise((resolve, reject) => {
        if(closed) { reject(new Error('Device-link session ended')); return; }
        const id = ++sequence;
        pending.set(id, {resolve, reject});
        try { worker.postMessage({id, operation, ...input,
          wasmURL: new URL(wasmURL, globalThis.location?.href || import.meta.url).href}); }
        catch(error) { pending.delete(id); reject(error); destroy(); }
      });
    }
  };
}

function localLink(url) {
  let state, closed = false;
  const abort = new AbortController();
  const transport = {
    terminate() { closed = true; abort.abort(); state?.destroy(); },
    postMessage(data) {
      const ready = state ? Promise.resolve(state) : import(url.href).then(async module => {
        state = await module.createLinkInstance(data.wasmURL, abort.signal);
        if(closed) state.destroy();
        return state;
      });
      ready.then(value => value.call(data.operation, data)).then(result => {
        if(closed) { result.seed?.fill(0); result.metadata?.fill(0); return; }
        transport.onmessage({data: {id: data.id, result}});
      }, error => {
        if(!closed) transport.onmessage({data: {id: data.id, error: error.message || String(error)}});
      });
    }
  };
  return transport;
}
