import {init} from './.build-embedded/plugins/PackageToJS/outputs/Package/index.js';
import {linkBackend} from './key-files.js';

let exports, session;
globalThis.onmessage = async({data}) => {
  try {
    let result;
    if(data.operation === 'begin' && !exports) {
      ({exports} = await init({module: fetch(data.wasmURL), getImports: () => ({})}));
      result = await exports.beginDeviceLink(data.label, await linkBackend());
      session = result.session;
      result = {request: result.request, parameter: result.parameter};
    } else if(data.operation === 'open' && session) {
      const current = session;
      session = undefined;
      result = await exports.openDeviceLink(current, data.response, data.expectedDC, data.now);
    } else { throw new Error('Device-link session ended'); }
    globalThis.postMessage({id: data.id, result});
  } catch(error) {
    globalThis.postMessage({id: data.id, error: error.message || String(error)});
  }
};
