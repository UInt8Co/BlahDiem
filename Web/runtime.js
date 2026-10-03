// BridgeJS generates both sides of the ABI; this adapter only normalizes JS inputs.
import {init} from './.build-embedded/plugins/PackageToJS/outputs/Package/index.js';
import {keyFiles, generateSigningKey} from './key-files.js';

const operations = new Set(['create', 'inspect', 'renew', 'account', 'domains', 'addDevice', 'removeDevice', 'prove']);
const kinds = new Set(['user', 'channel', 'bot', 'stickerSet', 'dc']);
const challengeKinds = new Set(['invocation', 'login', 'oauthConsent', 'accountLink', 'dcAdmin']);
const optional = ['account', 'device', 'challenge', 'query', 'keyID', 'sessionID', 'expiresAt', 'challengeKind', 'approvedChallenge', 'domains'];

function bytes(value, name, limit = 100_000) {
  if(!(Array.isArray(value) || value instanceof Uint8Array) || value.length > limit) throw new TypeError(`Invalid ${name} bytes`);
  const result = Array.from(value);
  if(!result.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) throw new TypeError(`Invalid ${name} bytes`);
  return result;
}

function backend(crypto) {
  for(const name of ['random', 'publicKey', 'sign', 'verify']) {
    if(typeof crypto?.[name] !== 'function') throw new TypeError(`Missing crypto.${name}`);
  }
  return crypto;
}

function validTime(value) { return Number.isSafeInteger(value) && value >= 0; }

/** Works in Window, DedicatedWorker and SharedWorker; no DOM or global callbacks. */
export async function createDiem(wasmURL = new URL('./diem.wasm', import.meta.url)) {
  const {exports} = await init({module: fetch(wasmURL), getImports: () => ({})});
  return {
    keyFiles: keyFiles(exports),
    generateSigningKey,
    async identityOperation(input, crypto) {
      if(!operations.has(input?.operation) || !kinds.has(input.kind) || typeof input.domain !== 'string' || input.domain.length > 253 ||
        typeof input.dcDomain !== 'string' || input.dcDomain.length > 253 ||
        typeof input.generation !== 'string' || !/^[1-9][0-9]{0,19}$/.test(input.generation) ||
        !validTime(input.now)) throw new TypeError('Invalid identity request');
      const request = {...input, profileLifetime: input.profileLifetime ?? 180 * 86400,
        deviceLifetime: input.deviceLifetime ?? 180 * 86400};
      for(const name of optional) request[name] ??= null;
      for(const name of ['dc', 'profile', 'device', 'challenge', 'query', 'approvedChallenge']) {
        if(request[name] === null && optional.includes(name)) continue;
        // A DC administration challenge can carry a 128 KiB document.
        request[name] = bytes(request[name], name, name === 'challenge' || name === 'approvedChallenge' ? 140_000 : 100_000);
      }
      if(request.dc.length !== 32) throw new TypeError('Invalid home identity');
      for(const name of ['keyID', 'sessionID', 'account']) {
        if(request[name] !== null && (typeof request[name] !== 'string' || !/^[0-9]{1,20}$/.test(request[name]))) {
          throw new TypeError(`Invalid ${name}`);
        }
      }
      if(request.expiresAt !== null && !validTime(request.expiresAt)) {
        throw new TypeError('Invalid challenge expiration');
      }
      if(request.operation === 'prove' && !challengeKinds.has(request.challengeKind)) {
        throw new TypeError('Invalid challenge kind');
      }
      for(const field of ['domains']) {
        if(request[field] !== null && (!Array.isArray(request[field]) || request[field].length > 16 ||
          request[field].some(value => typeof value !== 'string' || value.length > 253))) {
          throw new TypeError('Invalid profile domains');
        }
      }
      return exports.identityOperation(request, backend(crypto));
    },
    async dcSetup(input, crypto) {
      if(!validTime(input?.now)) throw new TypeError('Invalid DC setup time');
      return exports.dcSetup({data: bytes(input.data, 'data'),
        profile: input.profile == null ? null : bytes(input.profile, 'profile'), now: input.now,
        profileLifetime: input.profileLifetime ?? 90 * 86400,
        deviceLifetime: input.deviceLifetime ?? 90 * 86400}, backend(crypto));
    },
    async verifyDCProfile(domain, encoding, now, crypto) {
      if(typeof domain !== 'string' || domain.length > 253 || !validTime(now) || typeof crypto?.verify !== 'function') {
        throw new TypeError('Invalid DC discovery request');
      }
      return exports.verifyDCProfile(domain, bytes(encoding, 'profile'), now, crypto);
    },
    inspectChallenge(kind, encoding) {
      if(!challengeKinds.has(kind)) throw new TypeError('Invalid challenge kind');
      return exports.inspectChallenge(kind, bytes(encoding, 'challenge', 140_000));
    }
  };
}
