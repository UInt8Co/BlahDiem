function bytes(value, limit) {
  if(!(value instanceof Uint8Array || Array.isArray(value)) || value.length > limit ||
    !Array.from(value).every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
    throw new TypeError('Invalid device-link bytes');
  }
  return Array.from(value);
}

function parameter(value) {
  if(typeof value !== 'string' || value.length > 5462) throw new TypeError('Invalid device-link parameter');
  return value;
}

export function linkResponseInput(input) {
  if(typeof input?.domain !== 'string' || input.domain.length > 253 ||
    typeof input.transferIdentity !== 'boolean' || (!input.transferIdentity && input.metadata != null)) {
    throw new TypeError('Invalid device-link approval');
  }
  return {parameter: parameter(input.parameter), request: bytes(input.request, 4096),
    profile: bytes(input.profile, 65536), domain: input.domain, transferIdentity: input.transferIdentity,
    metadata: input.metadata == null ? null : bytes(input.metadata, 16384), now: Math.floor(Date.now() / 1000)};
}

export function deviceLink(exports, wasmURL, backend) {
  const sessions = new WeakMap();
  return {
    async begin(label) {
      if(typeof label !== 'string' || new TextEncoder().encode(label).length < 1 ||
        new TextEncoder().encode(label).length > 64) throw new TypeError('Invalid device-link label');
      const inWorker = typeof WorkerGlobalScope !== 'undefined' && globalThis instanceof WorkerGlobalScope;
      const worker = inWorker ? undefined : new Worker(new URL('./device-link-worker.js', import.meta.url), {type: 'module'});
      const pending = new Map();
      let sequence = 0, closed = false, opening = false;
      let nativeSession;
      const destroy = () => {
        closed = true;
        worker?.terminate();
        if(nativeSession) exports.destroyDeviceLink(nativeSession);
        nativeSession = undefined;
        for(const {reject} of pending.values()) reject(new Error('Device-link session ended'));
        pending.clear();
      };
      if(worker) worker.onmessage = ({data}) => {
        const call = pending.get(data.id);
        if(!call) return;
        pending.delete(data.id);
        data.error ? call.reject(new Error(data.error)) : call.resolve(data.result);
      };
      if(worker) worker.onerror = event => {
        for(const {reject} of pending.values()) reject(new Error(event.message || 'Device-link worker failed'));
        destroy();
      };
      if(worker) worker.onmessageerror = destroy;
      const call = async(operation, input) => {
        if(inWorker) {
          if(closed) throw new Error('Device-link session ended');
          if(operation === 'begin') {
            const result = await exports.beginDeviceLink(input.label, await backend());
            nativeSession = result.session;
            if(closed) { destroy(); throw new Error('Device-link session ended'); }
            return result;
          }
          const result = await exports.openDeviceLink(nativeSession, input.response, input.expectedDC, input.now);
          if(closed) throw new Error('Device-link session ended');
          return result;
        }
        return new Promise((resolve, reject) => {
          if(closed) { reject(new Error('Device-link session ended')); return; }
          const id = ++sequence;
          pending.set(id, {resolve, reject});
          try { worker.postMessage({id, operation, ...input}); }
          catch(error) { pending.delete(id); reject(error); destroy(); }
        });
      };
      try {
        const result = await call('begin', {label, wasmURL: new URL(wasmURL, globalThis.location?.href || import.meta.url).href});
        const session = Object.freeze({destroy});
        sessions.set(session, {
          async open(response, expectedDC) {
            try {
              if(opening || closed) throw new Error('Device-link session ended');
              opening = true;
              const dc = bytes(expectedDC, 32);
              if(dc.length !== 32) throw new TypeError('Invalid DC identity');
              const opened = await call('open', {response: bytes(response, 65536), expectedDC: dc, now: Math.floor(Date.now() / 1000)});
              return {...opened, profile: new Uint8Array(opened.profile),
                metadata: opened.metadata == null ? undefined : new Uint8Array(opened.metadata),
                keyFileContents: new Uint8Array(opened.keyFileContents)};
            } finally { destroy(); sessions.delete(session); }
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
    async inspect(value, request) {
      const inspected = exports.inspectDeviceLink(parameter(value), bytes(request, 4096));
      return {...inspected, device: new Uint8Array(inspected.device)};
    }
  };
}
