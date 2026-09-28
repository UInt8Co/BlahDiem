// BridgeJS generates both sides of the ABI; this adapter only normalizes JS inputs.
import {init} from './.build-embedded/plugins/PackageToJS/outputs/Package/index.js';

const operations = new Set(['create', 'inspect', 'renew', 'account', 'addDevice', 'removeDevice', 'prove']);
const optional = ['account', 'device', 'challenge', 'query', 'keyID', 'sessionID', 'expiresAt'];

/** Works in Window, DedicatedWorker and SharedWorker; no DOM or global callbacks. */
export async function createDiem(wasmURL = new URL('./diem.wasm', import.meta.url)) {
  const {exports} = await init({module: fetch(wasmURL), getImports: () => ({})});
  return {
    async identityOperation(input, crypto) {
      if(!operations.has(input?.operation) || typeof input.domain !== 'string' || input.domain.length > 253 ||
        typeof input.dcDomain !== 'string' || input.dcDomain.length > 253 ||
        typeof input.generation !== 'string' || !/^[1-9][0-9]{0,19}$/.test(input.generation) ||
        !Number.isSafeInteger(input.now) || input.now < 0) throw new TypeError('Invalid identity request');
      const request = {...input};
      for(const name of optional) request[name] ??= null;
      for(const name of ['dc', 'profile', 'device', 'challenge', 'query']) {
        const bytes = request[name];
        if(bytes === null && optional.includes(name)) continue;
        if(!(Array.isArray(bytes) || bytes instanceof Uint8Array) || bytes.length > 100_000 ||
          !bytes.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) throw new TypeError(`Invalid ${name} bytes`);
        request[name] = Array.from(bytes);
      }
      if(request.dc.length !== 32) throw new TypeError('Invalid home identity');
      for(const name of ['keyID', 'sessionID', 'account']) {
        if(request[name] !== null && (typeof request[name] !== 'string' || !/^[0-9]{1,20}$/.test(request[name]))) {
          throw new TypeError(`Invalid ${name}`);
        }
      }
      if(request.expiresAt !== null && (!Number.isSafeInteger(request.expiresAt) || request.expiresAt < 0)) {
        throw new TypeError('Invalid challenge expiration');
      }
      for(const name of ['random', 'publicKey', 'sign', 'verify']) {
        if(typeof crypto?.[name] !== 'function') throw new TypeError(`Missing crypto.${name}`);
      }
      return exports.identityOperation(request, crypto);
    }
  };
}
