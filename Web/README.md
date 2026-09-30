# BlahDiem for web clients

The WASM library runs BlahDiem's canonical profile and proof rules in windows,
dedicated workers and shared workers. BridgeJS generates the JavaScript ABI and
TypeScript declarations. WebCrypto supplies Ed25519 signing and Ed25519/P-256 verification;
private-key custody, backups, profile hosting and user consent belong to the caller.

```js
import {createDiem} from './diem.js';
const diem = await createDiem(new URL('./diem.wasm', import.meta.url));
const result = await diem.identityOperation(request, cryptoBackend);
```

## API

`diem.d.ts` and `bridge-js.d.ts` define the requests, results and crypto callbacks.
Bytes are arrays of integers from 0 to 255; the adapter also accepts `Uint8Array`.
64-bit identifiers use decimal strings. Operation times use safe integer Unix seconds.
Each asynchronous operation retains its own crypto backend.

- `identityOperation` manages hosted `user`, `channel`, `bot` and `stickerSet`
  identities. Specify `kind` and an operation: `create`, `inspect`, `renew`,
  `account`, `domains`, `addDevice`, `removeDevice` or `prove`. Native profile rules validate
  names, account numbers, homes and devices. `profileLifetime` and `deviceLifetime`
  are positive integer seconds, defaulting to 180 days. Profile lifetime must not
  exceed device lifetime. Results include ordered profile domains and profile/device validity intervals;
  callers own renewal scheduling and publication. Renewal also extends the home
  delegation to the device expiry.
For a user, `domains` replaces the ordered domain list and `usernameDomains` selects
which of those domains may be used as public usernames. At least one discovery domain
remains. Results return both lists; the caller republishes the signed revision at every
listed domain before requesting a DC profile check.

- `dcSetup` creates a DC identity or renews an existing one using encoded DC data.
  It returns the signed public profile and the operator device's certificate validity
  (`notBefore` and `expiresAt`, Unix seconds). No server device is created or certified.
  Pass `profile: null` to create, or the existing profile to renew. Only the public
  signed profile is uploaded; identity and device private keys remain in the browser.
  `profileLifetime` and `deviceLifetime` are positive integer seconds, both defaulting
  to 90 days. The requested profile lifetime must not exceed the certificate lifetime.
- `verifyDCProfile` verifies a public DC profile’s certificates, signature, validity,
  advertised discovery domain and required database generation without a signer.
  It returns the identity, profile version/digest, exact client endpoints and transport
  public key. The caller owns HTTPS fetching, transport selection, identity pinning and
  persistent version floors; this operation only requires the `verify` crypto callback.
- `inspectChallenge` decodes `invocation`, `login`, `oauthConsent`, `accountLink`
  and `dcAdmin` challenges into fields for session checks or consent UI. It does
  not authenticate the issuing server or grant approval.

For `prove`, set `challengeKind`, the received `challenge`, its expected
`expiresAt`, and `approvedChallenge` containing the exact bytes the application
checked or the user approved. Invocation and login proofs also require the
current `keyID` and `sessionID`; invocation proofs bind the exact `query` bytes.
The library checks the home, expiry, identity/device binding and native statement
rules before signing. Proofs need only the device signer; identity keys certify
and manage devices. Invalid requests reject without replacing another call's signer.

## Vendoring a release

Each successful `main` push publishes a GitHub release named `YYYYMMDD-<sha4>`.
Download a specific release and verify `SHA256SUMS`. Vendor its matching
`diem.js`, `diem.wasm`, declarations and license files together; retain the release
tag and `manifest.json` with the checksums and source revision.

Serve WASM as `application/wasm`. Supply an explicit WASM URL when relocating the
assets. The `.br` and `.gz` files require the corresponding `Content-Encoding`.
Consumers need no Swift toolchain or external runtime downloads.

## Build and test

Install Swift 6.4, the `swift-6.4.0-RELEASE_wasm-embedded` SDK, Binaryen 133,
Node 24 and pnpm. From `Web/`:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm exec playwright install --with-deps chromium
pnpm test
```

`BLAH_SWIFT`, `WASM_OPT` and `BLAH_BROWSER_EXECUTABLE` select installed tools.
Build output is in `Web/dist/`. The build pins dependencies, generates BridgeJS
bindings, minimizes the Embedded Swift binary and enforces artifact size limits.
Tests run real WebCrypto operations in Window, DedicatedWorker and SharedWorker.
The [release workflow](../.github/workflows/web-release.yml) owns CI tool installation,
testing and packaging.
