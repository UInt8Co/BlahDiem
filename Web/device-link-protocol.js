// Blah's device-link protocol over Diem's link machinery: the joining device opens a grant
// for the DC it expects, and Blah's opaque metadata travels only with seed transfer.
// Its own module keeps the link worker bundle small. It replaces every member of Diem's
// generic protocol, so it does not spread (and bundle) that one.
import {linkBytes, linkParameter} from './.build-embedded/checkouts/diem/Web/device-link-protocol.js';

export const blahLinkProtocol = {
  openInput(response, expectedDC) {
    const dc = linkBytes(expectedDC, 32);
    if(dc.length !== 32) throw new TypeError('Invalid DC identity');
    return {response: linkBytes(response, 65536), expectedDC: dc};
  },
  respondInput(input) {
    if(typeof input?.domain !== 'string' || input.domain.length > 253 ||
      (input.seed == null && input.metadata != null)) {
      throw new TypeError('Invalid device-link approval');
    }
    let seed, metadata, returned = false;
    try {
      const code = linkParameter(input.code), request = linkBytes(input.request, 4096), profile = linkBytes(input.profile, 65536);
      metadata = input.metadata == null ? null : linkBytes(input.metadata, 16384);
      seed = input.seed == null ? null : linkBytes(input.seed, 32);
      if(seed != null && seed.length !== 32) throw new TypeError('Invalid identity seed');
      const result = {code, request, profile, domain: input.domain, seed, metadata};
      returned = true;
      return result;
    } finally { if(!returned) { seed?.fill(0); metadata?.fill(0); } }
  },
  opened(result) {
    return {profile: new Uint8Array(result.profile), domain: result.domain, device: result.device,
      seed: result.seed == null ? undefined : new Uint8Array(result.seed),
      metadata: result.metadata == null ? undefined : new Uint8Array(result.metadata)};
  },
  open(exports, session, input) {
    return exports.openDeviceLink(session, input.response, input.expectedDC, input.now);
  },
  respond(exports, input, backend) {
    return exports.respondToDeviceLink(input, backend);
  },
  secrets(value) { return [value?.seed, value?.metadata]; }
};
