import {run} from './device-link.js';
const answer = port => run().then(result => port.postMessage({result}), error => port.postMessage({error: error.stack}));
if('onconnect' in globalThis) {
  globalThis.onconnect = event => { const port = event.ports[0]; port.start(); answer(port); };
} else {
  answer(globalThis);
}
