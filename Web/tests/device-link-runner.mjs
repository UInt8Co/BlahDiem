import assert from 'node:assert/strict';
import {readFile, writeFile} from 'node:fs/promises';

export async function runDeviceLinkTests(page, engine) {
  const windowResult = await page.evaluate(async() => Promise.race([
    (await import('/tests/device-link.js')).run(),
    new Promise((_, reject) => setTimeout(() => reject(new Error('Device link Window timed out')), 30_000))
  ]));
  assert.equal(windowResult.realm, 'window');
  console.log(`PASS ${engine} device link Window`);
  await capture(engine, 'Window', windowResult);
  for(const shared of [false, true]) {
    const result = await page.evaluate(shared => new Promise((resolve, reject) => {
      const worker = shared ? new SharedWorker('/tests/device-link-worker.js', {type: 'module'}) : new Worker('/tests/device-link-worker.js', {type: 'module'});
      const port = shared ? worker.port : worker;
      const timer = setTimeout(() => { cleanup(); reject(new Error('Device link worker timed out')); }, 30_000);
      const cleanup = () => { clearTimeout(timer); if(shared) port.close(); else worker.terminate(); };
      worker.onerror = event => { cleanup(); reject(new Error(event.message)); };
      port.onmessage = event => { cleanup(); event.data.error ? reject(new Error(event.data.error)) : resolve(event.data.result); };
      if(shared) port.start();
    }), shared);
    assert.equal(result.realm, 'worker');
    assert.ok(result.response.length > 0);
    console.log(`PASS ${engine} device link ${shared ? 'SharedWorker' : 'DedicatedWorker'}`);
    await capture(engine, shared ? 'SharedWorker' : 'DedicatedWorker', result);
  }
  console.log(`PASS ${engine} device link Window, DedicatedWorker and SharedWorker: native grants, browser responses, canonical records, request binding, bounds and rejection.`);
}

async function capture(engine, realm, result) {
  if(process.env.BLAH_DEVICE_LINK_GENERATE !== '1') return;
  const file = new URL('./device-link-browser.json', import.meta.url);
  let vectors = [];
  try { vectors = JSON.parse(await readFile(file, 'utf8')).vectors || []; }
  catch(error) { if(error.code !== 'ENOENT') throw error; }
  vectors = vectors.filter(value => value.engine !== engine || value.realm !== realm);
  vectors.push({engine, realm, response: result.response, deviceOnlyResponse: result.deviceOnlyResponse});
  vectors.sort((a, b) => (a.engine + a.realm).localeCompare(b.engine + b.realm));
  await writeFile(file, JSON.stringify({vectors}) + '\n');
}

// Standalone execution keeps failures in older suites from hiding these contract tests.
if(process.argv[1] && import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1]).href) {
  const {createServer} = await import('node:http');
  const {readFile} = await import('node:fs/promises');
  const {chromium, webkit} = await import('@playwright/test');
  const engines = process.argv.slice(2).length ? process.argv.slice(2) : ['chromium'];
  const server = createServer(async(req, res) => {
    try {
      const path = new URL(req.url, 'http://localhost').pathname;
      if(!/^\/(dist|tests)\/[a-zA-Z0-9.-]+$/.test(path)) {
        res.setHeader('Content-Type', 'text/html');
        res.end('<!doctype html><title>Device link tests</title>'); return;
      }
      res.setHeader('Content-Type', path.endsWith('.wasm') ? 'application/wasm' : 'text/javascript');
      res.end(await readFile(new URL('..' + path, import.meta.url)));
    } catch { res.writeHead(404); res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    for(const name of engines) {
      const engine = {chromium, webkit}[name];
      if(!engine) throw new Error(`Unknown browser: ${name}`);
      browser = await engine.launch({headless: true, executablePath: process.env.BLAH_BROWSER_EXECUTABLE,
        ...(name === 'chromium' ? {args: ['--no-sandbox']} : {})});
      const page = await browser.newPage();
      page.on('pageerror', error => console.error(error));
      await page.goto(`http://127.0.0.1:${server.address().port}`);
      await runDeviceLinkTests(page, name);
      await browser.close(); browser = undefined;
    }
  } finally {
    await browser?.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}
