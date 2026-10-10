import {execFileSync} from 'node:child_process';
import {mkdir, readFile, writeFile, copyFile, rm} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {gzipSync, brotliCompressSync, constants} from 'node:zlib';
import {build} from 'esbuild';

const web = fileURLToPath(new URL('.', import.meta.url));
const root = fileURLToPath(new URL('../', import.meta.url));
const scratch = `${web}.build-embedded`;
const generated = `${scratch}/plugins/PackageToJS/outputs/Package/`;
const output = `${web}dist/`;
const swift = process.env.BLAH_SWIFT || 'swift';
const optimizer = process.env.WASM_OPT || 'wasm-opt';
const sdk = 'swift-6.4.0-RELEASE_wasm-embedded';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
// The 6.4 SDK enables Embedded itself. JavaScriptKit's legacy opt-in also emits
// empty library objects, which drops the WASM callback exports needed by async work.
const run = (command, args, options = {}) => execFileSync(command, args, {cwd: root,
  env: {...process.env, JAVASCRIPTKIT_EXPERIMENTAL_EMBEDDED_WASM: 'false'}, ...options});
// Fail instead of PackageToJS's silent copy when the optimizer is absent.
const optimizerVersion = run(optimizer, ['--version'], {encoding: 'utf8'}).trim();
if(!optimizerVersion.includes('version 133 ')) throw new Error('Install pinned Binaryen 133 (wasm-opt).');
const swiftVersion = run(swift, ['--version'], {encoding: 'utf8'}).split('\n')[0];
if(!/Swift version 6\.4(?:\.0)?\s/.test(swiftVersion)) throw new Error('Use Swift 6.4 with the matching WASM SDK.');
const packageArgs = ['package', '--package-path', 'Web', '--scratch-path', scratch, '--swift-sdk', sdk, '--force-resolved-versions'];
run(swift, [...packageArgs, 'resolve'], {stdio: 'inherit'});
const diem = `${scratch}/checkouts/diem`;
const pins = JSON.parse(await readFile(web + 'Package.resolved', 'utf8')).pins;
const base = pins.find(pin => pin.identity === 'diem').state.revision;
const git = args => run('git', ['-C', diem, ...args], {encoding: 'utf8'});
if(git(['rev-parse', 'HEAD']).trim() !== base) throw new Error('Unexpected Diem checkout revision.');
if(git(['status', '--porcelain']).trim()) {
  throw new Error('Diem checkout differs from its pinned revision. Use a clean Web/.build-embedded.');
}
run(swift, [...packageArgs, '-j', '4', '-Xswiftc', '-Osize', '-Xswiftc', '-gnone',
  'js', '-c', 'release', '--no-optimize'], {stdio: 'inherit'});
await rm(output, {recursive: true, force: true});
await mkdir(output, {recursive: true});
// Strip before optimizing: retained DWARF inhibits some Binaryen transformations.
run(optimizer, [`${generated}BlahDiemWeb.wasm`, '--strip-dwarf', '--strip-debug', '-o', `${output}stripped.wasm`]);
run(optimizer, [`${output}stripped.wasm`, '-Oz', '--strip-producers', '-o', `${output}diem.wasm`]);
await rm(`${output}stripped.wasm`);
await build({entryPoints: [`${web}runtime.js`], outfile: `${output}diem.js`, bundle: true,
  format: 'esm', platform: 'browser', target: 'es2022', minify: true, legalComments: 'none'});
await copyFile(`${generated}bridge-js.d.ts`, `${output}bridge-js.d.ts`);
await copyFile(`${web}diem.d.ts`, `${output}diem.d.ts`);
await copyFile(`${root}LICENSE`, `${output}LICENSE`);
const swiftResources = JSON.parse(run(swift, ['-print-target-info'], {encoding: 'utf8'})).paths.runtimeResourcePath;
const notices = await Promise.all([resolve(swiftResources, '../../share/swift/LICENSE.txt'), `${scratch}/checkouts/JavaScriptKit/LICENSE`, `${web}node_modules/@bjorn3/browser_wasi_shim/LICENSE-MIT`, `${web}node_modules/@hpke/core/LICENSE`, `${web}node_modules/@hpke/core/../common/LICENSE`, `${web}node_modules/@noble/curves/LICENSE`, `${web}node_modules/@noble/curves/../hashes/LICENSE`, `${diem}/LICENSE`].map(path => readFile(path, 'utf8')));
await writeFile(`${output}THIRD_PARTY_LICENSES`, notices.map(text => text.trimEnd()).join('\n\n---\n\n') + '\n');
await copyFile(`${web}README.md`, `${output}README.md`);
await writeFile(`${output}package.json`, JSON.stringify({name: '@blahim/diem-web', version: process.env.GITHUB_REF_NAME?.match(/^web-v(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)$/)?.[1] || '0.0.0-dev', type: 'module',
  license: 'MIT', types: './diem.d.ts', exports: {'.': {types: './diem.d.ts', default: './diem.js'}, './diem.wasm': './diem.wasm'}}, null, 2) + '\n');
const files = {};
for(const name of ['diem.js', 'diem.wasm', 'diem.d.ts', 'bridge-js.d.ts', 'package.json', 'LICENSE', 'THIRD_PARTY_LICENSES', 'README.md']) {
  const bytes = await readFile(output + name);
  files[name] = {bytes: bytes.length, sha256: hash(bytes)};
  if(name.endsWith('.js') || name.endsWith('.wasm')) {
    const compressed = {gz: gzipSync(bytes, {level: 9}), br: brotliCompressSync(bytes, {
      params: {[constants.BROTLI_PARAM_QUALITY]: 11}
    })};
    for(const [extension, body] of Object.entries(compressed)) {
      await writeFile(`${output}${name}.${extension}`, body);
      files[`${name}.${extension}`] = {bytes: body.length, sha256: hash(body)};
    }
  }
}
// Includes the key-file codec, HPKE and Noble's P-256 public-point derivation
// for complete private-key imports on Safari (about 136 KB of JS in total).
// Paper keys add Diem's 13 KB BIP 39 word list to the WASM.
if(files['diem.wasm'].bytes > 465_000 || files['diem.wasm.br'].bytes > 165_000 || files['diem.js'].bytes > 140_000) {
  throw new Error('Web artifact exceeds its size budget; inspect before releasing.');
}
const source = {repository: 'https://github.com/UInt8Co/BlahDiem',
  commit: run('git', ['rev-parse', 'HEAD'], {encoding: 'utf8'}).trim(),
  dirty: !!run('git', ['status', '--porcelain'], {encoding: 'utf8'}).trim()};
await writeFile(`${output}manifest.json`, JSON.stringify({format: 1, source, swift: swiftVersion, sdk,
  binaryen: optimizerVersion, files}, null, 2) + '\n');
const checksums = [...Object.entries(files).map(([name, info]) => `${info.sha256}  ${name}`),
  `${hash(await readFile(output + 'manifest.json'))}  manifest.json`];
await writeFile(output + 'SHA256SUMS', checksums.join('\n') + '\n');
console.log(JSON.stringify({wasm: files['diem.wasm'], brotli: files['diem.wasm.br'], js: files['diem.js']}, null, 2));
