# BlahDiem for web clients

The WASM library runs BlahDiem's canonical profile and proof rules in windows,
dedicated workers and shared workers. BridgeJS generates the JavaScript ABI and
TypeScript declarations. WebCrypto supplies Ed25519 signing and Ed25519/P-256 verification;
BlahDiem owns password-protected CBOR key files and key serialization. Applications own
storage, unlock lifetimes, profile hosting and user consent.

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
For a user, `domains` replaces the ordered domain list. Every domain is a username
candidate, and at least one domain remains. The caller republishes the signed revision
at every listed domain before requesting a DC profile check. Activation and ordering
of verified names are account settings.

An existing DC profile is also accepted as a `user` (or `dc`) identity for inspection,
device management, renewal and proofs. It remains a DC profile, permanently hosted by
itself as account 777000. DC creation uses `dcSetup`; changing its account or home is refused.

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

## Key files

`keyFiles.create(password)` returns an unlocked custody session. `session.seal(contents)`
produces a binary CBOR file; `keyFiles.unlock(bytes, password)` verifies and opens a file,
returning `{session, contents}`. `session.open(bytes)` and `session.seal(contents)` reuse
the unlocked recipient without retaining the password or repeating PBKDF2. Call
`session.destroy()` when locking or discarding a session. In-flight operations must finish
before the application considers its custody locked. `keyFiles.inspect(bytes)` returns
unverified display identity and salt only; it never grants authority.

Use `generateSigningKey()` for browser Ed25519 keys. Contents include the signed profile
and identity and/or device keys; `diem.d.ts` owns the browser shape. Recovery files can
contain only an identity key, device files only a device key, and browser backups both.
The native `KeyFile` contract defines the CBOR and password/HPKE rules. Recovery files
are portable between native clients, Chromium and Safari, including existing files.
The bundled `@hpke/core` implementation uses WebCrypto; `@noble/curves` supplies the
P-256 public point for Safari-compatible private-key imports. No external scripts are requested.
Downloads use `.cbor` and `application/cbor`. JSON files are rejected.

## Vendoring a release

Each successful `main` push publishes a GitHub release named `YYYYMMDD-<sha4>`.
Download a specific release and verify `SHA256SUMS`. Vendor its matching
`diem.js`, `diem.wasm`, declarations and license files together; retain the release
tag and `manifest.json` with the checksums and source revision.

Serve WASM as `application/wasm`. Supply an explicit WASM URL when relocating the
assets. The `.br` and `.gz` files require the corresponding `Content-Encoding`.
Consumers need no Swift toolchain or external runtime downloads.

### Publish to S3

To mirror web releases to one or more buckets, set the repository's GitHub Actions
secret `WEB_RELEASE_S3_TARGETS` to a JSON array with one entry per destination:

```json
[
  {
    "bucket": "blahdiem-releases",
    "prefix": "libraries/blahdiem",
    "region": "us-east-1",
    "accessKeyId": "<access key>",
    "secretAccessKey": "<secret key>"
  },
  {
    "bucket": "web-library-mirror",
    "prefix": "blahdiem",
    "endpointUrl": "https://s3.example.com",
    "region": "us-east-1",
    "accessKeyId": "<mirror access key>",
    "secretAccessKey": "<mirror secret key>"
  }
]
```

Each entry requires `bucket`, `accessKeyId` and `secretAccessKey`. `prefix` defaults
to the bucket root (leading/trailing slashes are ignored), and `region` defaults to
`us-east-1`. Set `endpointUrl` for S3-compatible storage and `sessionToken` when using
temporary credentials. Give each credential permission to upload objects below its
prefix; bucket access and CORS policies remain operator-managed.

The release job uploads the uncompressed files in `Web/dist/` to
`s3://<bucket>/<prefix>/<YYYYMMDD-sha4>/`, using the same tag as the GitHub release.
JS/WASM files carry their media types for direct browser use; configure delivery-time
compression on the CDN. The archive and `.gz`/`.br` variants are only published on GitHub.
The original manifest and checksums still describe the complete GitHub release.
An unset secret or `[]` skips S3 uploads. Invalid configuration or any failed upload
fails the job; rerunning it replaces the same tag's objects without deleting other
releases. GitHub release publishing still runs when S3 is unconfigured.

The [uploader](../Scripts/upload-web-release.mjs) uses the AWS CLI available on the
release runner. Run its checks locally with
`node --test Scripts/upload-web-release.test.mjs`; no bucket credentials are needed.

## Build and test

Install Swift 6.4, the `swift-6.4.0-RELEASE_wasm-embedded` SDK, Binaryen 133,
Node 24 and pnpm. From `Web/`:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm exec playwright install --with-deps chromium
pnpm test chromium
```

For Safari coverage, install Playwright WebKit on macOS with
`pnpm exec playwright install webkit`, then run `pnpm test webkit` against the same
`Web/dist/` package. `pnpm test` without browser arguments runs both engines.
CI builds once on Linux, checks Chromium there and checks the same artifacts with
WebKit on macOS. Both checks must pass before publication. Linux WebKit uses a
different cryptographic backend with intermittent Ed25519 key-generation failures;
macOS exercises Safari's native backend and private-key import restrictions.

`BLAH_SWIFT`, `WASM_OPT` and `BLAH_BROWSER_EXECUTABLE` select installed tools (the browser
override applies to Chromium).
Build output is in `Web/dist/`. The build pins dependencies, generates BridgeJS
bindings, minimizes the Embedded Swift binary and enforces artifact size limits.
Tests check the RFC 9180 derivation vector and run real WebCrypto operations in Window,
DedicatedWorker and SharedWorker under Chromium and WebKit. They enforce Cocoa WebKit's
private-key import restriction even on Linux, and retain native and pre-fix browser files.
The [release workflow](../.github/workflows/web-release.yml) owns CI tool installation,
testing and packaging.
