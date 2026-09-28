# BlahDiem for web clients

This package compiles the canonical BlahDiem/Diem profile and proof rules to WASM.
BridgeJS generates the Swift/JavaScript ABI and TypeScript declarations. The bundled
ES module works in a window, dedicated worker or shared worker; it needs no DOM,
global callbacks, cross-origin isolation, or third-party runtime downloads.

```js
import {createDiem} from './diem.js';
const diem = await createDiem(new URL('./diem.wasm', import.meta.url));
const result = await diem.identityOperation(request, cryptoBackend);
```

`request` is the generated `IdentityRequest` type in `bridge-js.d.ts`. Operations are
`create`, `inspect`, `renew`, `account`, `addDevice`, `removeDevice` and `prove`.
Profile and proof bytes always come from Swift. Decimal strings preserve 64-bit
identifiers. The backend supplies Ed25519 public keys and asynchronous sign/verify
callbacks; private key storage, encryption, profile hosting, and user consent belong
to the client. Each operation owns its backend, so concurrent callers cannot replace
one another's signer. Invalid requests reject their promise.

Serve `diem.js` and `diem.wasm` together, using `application/wasm` for the latter.
Pass an explicit URL when copying the files to a different directory. Precompressed
`.br`/`.gz` copies are provided for servers that negotiate `Content-Encoding`;
do not serve compressed bytes as unencoded WASM. No service worker is required.

## Build and test

Install Swift 6.4, its `swift-6.4.0-RELEASE_wasm-embedded` SDK, Binaryen 133 and Node 24.
The [web release workflow](../.github/workflows/web-release.yml) uses the official Swift
Docker image and installs the matching WebAssembly SDK from Swift.org with a pinned checksum.
From this directory run `pnpm install --frozen-lockfile`, `pnpm build`, then
`pnpm exec playwright install --with-deps chromium` and `pnpm test`.
`BLAH_BROWSER_EXECUTABLE` selects an existing Chromium installation.
Generated output is in `Web/dist/`; normal consumers need neither Swift nor Binaryen.
The build fails if the optimizer is missing or the artifact exceeds the size budget.

The build uses Swift 6.4 Embedded with `-Osize`, omits debug output, strips
remaining SDK debug sections, then runs Binaryen `-Oz`. It bundles/minifies the
generated BridgeJS module with JavaScriptKit and its WASI shim. Dependencies and
tools are pinned. `manifest.json` records source revision, tools, sizes and hashes;
`SHA256SUMS` covers all release files. Never mix the JS and WASM from different builds.

The pinned Diem revision supports Embedded directly. The build rejects unexpected
changes to its dependency checkout; no local source patches are needed.

The web release workflow tests workers and uploads artifacts for pull requests and
main. Each successful push build on `main` automatically tags the built commit and
publishes its tested files and archive in a GitHub release named `YYYYMMDD-<sha4>`.
The date is the commit's UTC date and `sha4` is the first four hexadecimal characters
of its SHA; reruns reuse the same release. Pull requests and manual builds only upload
workflow artifacts. Download a specific release, verify its checksums, and vendor the
files together; do not fetch a mutable latest build at application runtime.

## Size investigation

The previous tweb-owned release was 10,534,395 bytes, including about 4 MB of debug
and symbol information. Its build silently skipped Binaryen when `wasm-opt` was
missing. Stripping alone reduced it to 5,880,578 bytes; `-Oz` reduced it to
4,027,692 bytes. The regular Swift typed BridgeJS build was approximately 4 MB raw /
1.1 MB Brotli. Swift 6.4 Embedded reduces that to roughly 0.32 MB raw / 0.12 MB Brotli;
`manifest.json` contains exact sizes for each build. Brotli is a transfer size,
not the decoded module size.

Domain validation and bot-name checks operate on ASCII bytes, avoiding unnecessary
Unicode casing and character traversal. The linker retains the Unicode tables needed
by Swift's string equality and hashing in the general CBOR decoder; dropping those
tables would change existing text/map semantics. Unused table sections are discarded.
The SDK enables Embedded mode directly. JavaScriptKit's legacy environment opt-in is
disabled because its empty library objects omit async callback exports with this SDK.
The executable uses the WASI reactor ABI so the same generated module works in windows
and workers. Native contract tests and real browser crypto/proof tests cover the change.
