# BlahDiem for web clients

The WASM library runs BlahDiem's canonical profile and proof rules in windows,
dedicated workers and shared workers. It is Diem's web runtime with Blah's operations
added: one WASM links Diem's `DiemWeb` library and Blah's BridgeJS executable, and one
JavaScript bundle spreads Diem's client (`seeds`, `deviceKeys`, `hosting`, `deviceLink`)
and adds Blah's. [Diem's web README](https://github.com/UInt8Co/diem/blob/main/Web/README.md) is the contract for that generic API:
profile hosting, recovery words and seed custody, device keys, the device-link machinery
and its Content Security Policy. This page covers only what Blah adds or changes.
Applications own encrypted seed storage, platform key persistence, publication and user
consent.

```js
import {createDiem} from './diem.js';
const diem = await createDiem(new URL('./diem.wasm', import.meta.url));
const result = await diem.identityOperation(request, cryptoBackend);
```

## API

`diem.d.ts` and `bridge-js.d.ts` define the requests, results and crypto callbacks;
`diem.d.ts` imports Diem's generic declarations from `diem-web.d.ts`. Ship all three.
`CryptoBackend` and its callbacks are Diem's.
Bytes are arrays of integers from 0 to 255; the adapter also accepts `Uint8Array`.
64-bit identifiers use decimal strings. Operation times use safe integer Unix seconds.
Each asynchronous operation retains its own crypto backend.

- `identityOperation` manages hosted `user`, `channel`, `bot` and `stickerSet`
  identities. Specify `kind` and an operation: `create`, `enroll`, `inspect`, `renew`,
  `account`, `home`, `domains`, `addDevice`, `removeDevice` or `prove`. Native profile rules validate
  names, account numbers, homes and devices. `profileLifetime` and `deviceLifetime`
  are positive integer seconds, defaulting to 180 days. Profile lifetime must not
  exceed device lifetime. Results include ordered profile domains and profile/device validity intervals;
  callers own renewal scheduling and publication. Renewal also extends the home
  delegation to the device expiry.
`dc` names the DC the caller is acting at. Inspection, renewal, domain and device changes
work whichever DC hosts the identity; `namespace` is empty unless `dc` is its home. `prove`
and `account` require `dc` to be the home and otherwise reject with `wrongHome`. Read the
current home from `verifyProfile`.
For a user, `home` moves the identity to `dc`: a later home epoch with no account, which
the destination allocates at signup. Whichever DC receives that profile ends the old
hosting's account. Moving to the current home, or a DC profile, is refused.
`domains` replaces the ordered domain list under each kind’s native rules (a sticker
set keeps exactly one). Every domain is a username
candidate, and at least one domain remains. The caller republishes the signed revision
at every listed domain before requesting a DC profile check. Activation and ordering
of verified names are account settings.

An existing DC profile is also accepted as a `user` (or `dc`) identity for inspection,
device management, renewal and proofs. It remains a DC profile, permanently hosted by
itself as account 777000. DC creation uses `dcSetup`; changing its account or home is refused.

- `dcSetup` creates a DC identity or renews an existing one. `data` holds the DC
  profile fields as a canonical CBOR map, as signed in the Diem profile content: the
  discovery domains at key 9 and Blah's map at `"com.blahim"`:
  `{9: [domains], "com.blahim": {0: 5, 2: endpoints, 3: BIDCOM endpoints, 4: transport
  key, 5: namespace generation}}` (`DCProfile` owns the keys inside Blah's map). Any other
  integer key is refused. Before the Diem v5 wire, the DC fields sat at keys 16–21 of
  `data` itself; that layout is now rejected.
  It returns the signed public profile and its expiry (`expiresAt`, Unix seconds).
  The operator certificate's `notBefore` and `expiresAt` are in
  `devices.find(device => device.current)`. No server device is created or certified.
  Pass `seed` (32 entropy bytes) and `device` from `deviceKeys.generate()`.
  Omit `profile` to create, or pass the existing profile to renew. Renewal enrolls the
  provided fresh device and optionally prunes the device IDs in `removeDevices`.
  Only the public signed profile is uploaded. The ephemeral setup device is forgotten
  after publication; subsequent renewal derives the identity from recovery words.
  `profileLifetime` and `deviceLifetime` are positive integer seconds, both defaulting
  to 90 days. The requested profile lifetime must not exceed the certificate lifetime.
- `verifyDCProfile` verifies a public DC profile’s certificates, signature, validity,
  advertised discovery domain and required database generation without a signer.
  It returns the identity, profile version/digest, exact client endpoints and transport
  public key. The caller owns HTTPS fetching, transport selection, identity pinning and
  persistent version floors; this operation only requires the `verify` crypto callback.
- `verifyProfile(encoding, now, crypto)` verifies a stored public `user`, `channel`,
  `bot`, `stickerSet`, `dc` or `application` profile without domain binding or private keys; only
  `crypto.verify` is required. Diem validates the record, every device certificate
  and the content signature at the profile's `notBefore`; BlahDiem validates its kind
  and its `com.blahim` fields. It replaces Diem's generic `verifyProfile`. Invalid signatures or structure reject with the native error
  code (for example `invalidSignature` or `invalidProfile`).
  The returned `ProfileInfo` contains `id` (lowercase hex), `kind`, `generation`,
  `revision`, `notBefore`, `expiresAt`, `lapsed`, ordered `domains`, and nullable
  `home: {dc, account, epoch}`. Home `dc` is the DC identity/federation key ID in hex;
  `account` is null until allocated. All returned integers are decimal strings.
  `lapsed` is true when `now < notBefore` or `now >= expiresAt`; such profiles still
  verify because the server returns its latest stored profile even after expiry.
  A DC's home is itself, account `777000`, epoch `1`. Hosted profiles may have no home.
  `application` is non-null only for application profiles and holds their decoded
  content (name, download URL, bot, OAuth client data, push proxies and version
  boundaries); see `ApplicationInfo` in `diem.d.ts`.
  This is a stateless check: callers bind the result to the expected identity and
  retain monotonic generation/revision floors. Listed domains are signed claims,
  not proof of current domain control; `lapsed` describes the profile window only.
- `applicationWirePair(source)` returns `{apiID, apiHash}`, the application's public
  MTProto `api_id` (a number above every DC-local legacy ID) and `api_hash`, derived by
  BlahDiem from the identity ID. `source` is a verified `application` `ProfileInfo` or an
  identity ID in lowercase hex; any other profile kind or malformed ID throws `TypeError`.
  A bare ID is not checked to belong to an application, so verify its profile first.
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

## Recovery

Recovery words, `seeds` and `deviceKeys` are Diem's. Recovery-word sign-in fetches the
current trusted profile, checks it with `verifyProfile`, derives
`seeds.identity(entropy, expectedIdentityPublicKey)`, generates a fresh device, and uses
`identityOperation` with `operation:'enroll'`. Enrollment verifies the existing profile
and identity, preserves its devices and signed revision chain, and certifies the fresh
device. Persist custody and publish the returned revision before proving login.

To claim names, sign them with `identityOperation`'s `create` or `domains`, persist that
revision, then publish it with Diem's `hosting.publish`.

## QR device linking

`deviceLink.begin`, `inspect` and `session.destroy` are Diem's. Put `parameter` in the QR
URL's `blah` parameter. Blah's `respond` and `open` apply Blah's rules
(see `DeviceAuthority.md`):

```js
const response = await diem.deviceLink.respond({
  code: parameter, request, profile: publishedProfile, domain,
  seed: allowThisDeviceToApproveSignIns ? entropy : undefined,
  metadata: allowThisDeviceToApproveSignIns ? portableSettings : undefined
});
const opened = await diem.deviceLink.open(session, response, expectedDC);
// opened = {profile, domain, device: {privateKey: CryptoKey, publicKey: Uint8Array},
//           seed?: Uint8Array, metadata?: Uint8Array}
```

Seed transfer is opt-in; the approval toggle defaults off. Metadata is opaque application
bytes, at most 16 KiB, allowed only with seed transfer; it travels as bytes in the grant's
`com.blahim` field. The grant's profile must be a user with an allocated account whose
home is active. `open` also requires that home to be the expected DC's 32-byte identity,
and checks these rules before a transferred seed is opened. Success or failure ends the
session. Vendor `device-link-worker.js` beside `diem.js`: it is Blah's link worker, built
from Diem's session machinery with Blah's protocol.

## Vendoring a release

Each successful `main` push publishes a GitHub release named `YYYYMMDD-<sha4>`.
Download a specific release and verify `SHA256SUMS`. Vendor its matching
`diem.js`, `device-link-worker.js`, `diem.wasm`, declarations (`diem.d.ts`,
`diem-web.d.ts`, `bridge-js.d.ts`) and license files together; retain the release tag and
`manifest.json` with the checksums and source revision.

Serve WASM as `application/wasm`. Supply an explicit WASM URL when relocating the
assets. The `.br` and `.gz` files require the corresponding `Content-Encoding`.
Consumers need no Swift toolchain or external runtime downloads.

Cross-origin hosting and its Content Security Policy follow Diem's web README.

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

`build.mjs` first resolves the package into `Web/.build-embedded`. That creates the
checkout of the pinned diem revision, whose `Web/Sources/DiemWeb` the `DiemWeb` target
compiles and whose JavaScript modules `runtime.js`, `device-link-protocol.js` and
`device-link-worker.js` import (esbuild resolves their packages from this
`node_modules`). Build through `build.mjs`: a plain `swift build` without that scratch
path has no `DiemWeb` sources. `Package.swift` and `Package.resolved` pin diem; the root
package's pin must match.

For Safari coverage, install Playwright WebKit on macOS with
`pnpm exec playwright install webkit`, then run `pnpm test webkit` against the same
`Web/dist/` package. `pnpm test` without browser arguments runs both engines.
CI builds once on Linux, checks Chromium there and checks the same artifacts with
WebKit on macOS. Both checks must pass before publication.

`BLAH_SWIFT`, `WASM_OPT` and `BLAH_BROWSER_EXECUTABLE` select installed tools (the browser
override applies to each requested browser; select one engine when overriding).
Build output is in `Web/dist/`. The build pins dependencies, generates BridgeJS
bindings, minimizes the Embedded Swift binary and enforces artifact size limits.
Tests run Blah's operations in Window, DedicatedWorker and SharedWorker under Chromium
and WebKit: identity operations, profile and challenge rules, DC setup and discovery,
recovery, and Blah device links, including native/browser HPKE interoperability
(`tests/device-link-native.json`, and `tests/device-link-browser.json`, which the root
package's `swift test` opens natively). Regenerate the browser fixture after a wire
change with `BLAH_DEVICE_LINK_GENERATE=1 node tests/device-link-runner.mjs chromium webkit`.
Diem's web tests cover the generic runtime.
The [release workflow](../.github/workflows/web-release.yml) owns CI tool installation,
testing and packaging.
