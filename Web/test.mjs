import {createServer} from 'node:http';
import {readFile, writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {chromium} from '@playwright/test';
import assert from 'node:assert/strict';
const web = fileURLToPath(new URL('.', import.meta.url));
const server = createServer(async(req, res) => {
  try {
    const path = new URL(req.url, 'http://localhost').pathname;
    if(!/^\/(dist|tests)\/[a-zA-Z0-9.-]+$/.test(path)) {
      res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><title>BlahDiem web test</title>'); return;
    }
    res.setHeader('Content-Type', path.endsWith('.wasm') ? 'application/wasm' : 'text/javascript');
    res.end(await readFile(web + path));
  } catch { res.writeHead(404); res.end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({headless: true, executablePath: process.env.BLAH_BROWSER_EXECUTABLE, args: ['--no-sandbox']});
  const page = await browser.newPage();
  page.on('pageerror', error => console.error(error));
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  const windowResult = await page.evaluate(async() => Promise.race([
    (await import('/tests/scenario.js')).run(),
    new Promise((_, reject) => setTimeout(() => reject(new Error('Window test timed out')), 30_000))
  ]));
  assert.equal(windowResult.realm, 'window');
  if(process.env.BLAH_KEY_FILE_VECTOR) await writeFile(process.env.BLAH_KEY_FILE_VECTOR, JSON.stringify({file: windowResult.keyFile}) + '\n');
  for(const shared of [false, true]) {
    const result = await page.evaluate(shared => new Promise((resolve, reject) => {
      const worker = shared ? new SharedWorker('/tests/worker.js', {type: 'module'}) : new Worker('/tests/worker.js', {type: 'module'});
      const port = shared ? worker.port : worker;
      const timer = setTimeout(() => reject(new Error('Worker timed out')), 30_000);
      const cleanup = () => { clearTimeout(timer); if(shared) port.close(); else worker.terminate(); };
      worker.onerror = event => { cleanup(); reject(new Error(event.message)); };
      port.onmessage = event => { cleanup(); event.data.error ? reject(new Error(event.data.error)) : resolve(event.data.result); };
      if(shared) port.start();
    }), shared);
    assert.equal(result.realm, 'worker');
  }
  console.log('PASS Window, DedicatedWorker and SharedWorker: hosted identity kinds, all challenge/proof kinds, DC setup/recovery, HPKE key files and native interoperability, concurrent signers, devices and rejection.');
} finally {
  await browser?.close();
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
