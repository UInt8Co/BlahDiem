import {run} from './scenario.js';
const answer = (port, realm) => {
  port.onmessage = event => run({engine: event.data.engine, realm}).then(result => port.postMessage({result}),
    error => port.postMessage({error: `${error.name}: ${error.message}\n${error.stack}`}));
};
if('onconnect' in globalThis) {
  globalThis.onconnect = event => { const port = event.ports[0]; answer(port, 'SharedWorker'); port.start(); };
} else {
  answer(globalThis, 'DedicatedWorker');
}
