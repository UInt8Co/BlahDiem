import {init} from './.build-embedded/plugins/PackageToJS/outputs/Package/index.js';
import {deviceKeys} from './crypto-support.js';
import {linkBackend} from './link-crypto.js';

// SharedWorker cannot spawn workers. Its fallback owns a separate, wipeable WASM heap.
export async function createLinkInstance(wasmURL, signal) {
  let native = await init({module: fetch(wasmURL, {signal}), getImports: () => ({})});
  let session, device, closed = false, active = false;
  const dispose = () => {
    if(active || !native) return;
    const current = native, ending = session;
    native = undefined;
    session = device = undefined;
    try { if(ending) current.exports.destroyDeviceLink(ending); }
    finally { new Uint8Array(current.instance.exports.memory.buffer).fill(0); }
  };
  return {
    destroy() { closed = true; dispose(); },
    async call(operation, input) {
      if(closed || active) throw new Error('Device-link session ended');
      active = true;
      let opened, seed, returned = false;
      try {
        let result;
        if(operation === 'begin' && !session) {
          device = await deviceKeys.generate();
          result = await native.exports.beginDeviceLink(input.label, await linkBackend(device));
          session = result.session;
          result = {request: result.request, parameter: result.parameter};
        } else if(operation === 'open' && session) {
          const current = session;
          session = undefined;
          opened = await native.exports.openDeviceLink(current, input.response, input.expectedDC, input.now);
          seed = opened.seed == null ? undefined : new Uint8Array(opened.seed);
          result = {...opened, seed, device};
        } else if(operation === 'respond' && !session) {
          result = await native.exports.respondToDeviceLink(input.input, await linkBackend());
        } else { throw new Error('Device-link session ended'); }
        if(closed) throw new Error('Device-link session ended');
        returned = true;
        return result;
      } finally {
        opened?.seed?.fill(0);
        if(!returned) { seed?.fill(0); opened?.metadata?.fill(0); }
        input.input?.seed?.fill(0);
        input.input?.metadata?.fill(0);
        active = false;
        if(operation !== 'begin' || !returned) closed = true;
        if(closed) dispose();
      }
    }
  };
}

// Importing this module in SharedWorker exposes only the isolated-instance factory.
if(typeof DedicatedWorkerGlobalScope !== 'undefined' && globalThis instanceof DedicatedWorkerGlobalScope) {
  let state;
  globalThis.onmessage = async({data}) => {
    let result, keep = false;
    try {
      state ??= await createLinkInstance(data.wasmURL);
      result = await state.call(data.operation, data);
      keep = data.operation === 'begin';
      globalThis.postMessage({id: data.id, result}, result.seed ? [result.seed.buffer] : []);
    } catch(error) {
      keep = false;
      globalThis.postMessage({id: data.id, error: error.message || String(error)});
    } finally {
      if(result?.seed?.byteLength) result.seed.fill(0);
      result?.metadata?.fill(0);
      data.input?.seed?.fill(0);
      data.input?.metadata?.fill(0);
      if(!keep) { state?.destroy(); state = undefined; globalThis.close(); }
    }
  };
}
