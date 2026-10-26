import {installFixtureCrypto} from './device-link-fixture-crypto.js';

// Queue startup RPCs while this test-only bootstrap installs fixed crypto inputs.
const messages = [];
const hold = event => { event.stopImmediatePropagation(); messages.push(event.data); };
globalThis.addEventListener('message', hold);
const vector = await (await fetch(new URL('./device-link-native.json', import.meta.url))).json();
await installFixtureCrypto(vector);
Date.now = () => vector.now * 1000;
const target = new URL(import.meta.url).searchParams.get('target');
await import(target);
globalThis.removeEventListener('message', hold);
for(const data of messages) globalThis.dispatchEvent(new MessageEvent('message', {data}));
