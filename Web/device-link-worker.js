// Blah's link worker: Diem's session machinery over this WASM with Blah's protocol.
import {init} from './.build-embedded/plugins/PackageToJS/outputs/Package/index.js';
import {linkInstanceFactory, serveLinkWorker} from './.build-embedded/checkouts/diem/Web/device-link-session.js';
import {blahLinkProtocol} from './device-link-protocol.js';

export const createLinkInstance = linkInstanceFactory(init, blahLinkProtocol);
serveLinkWorker(createLinkInstance, blahLinkProtocol);
