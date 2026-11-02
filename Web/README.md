# BlahDiem for web clients

The WASM library runs BlahDiem's canonical profile and proof rules in windows,
dedicated workers and shared workers. BridgeJS generates the JavaScript ABI and
TypeScript declarations. WebCrypto signs with seed-derived Ed25519 identity keys and
non-extractable ECDSA P-256 device keys, and verifies both algorithms. Applications own
encrypted seed storage, platform key persistence, publication and user consent.

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
  profile fields as a CBOR map, as signed in the Diem profile content: the discovery
  domains at key 9 and the DC fields from key 16 (`DCProfile` owns the keys).
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
  `bot`, `stickerSet` or `dc` profile without domain binding or private keys; only
  `crypto.verify` is required. Diem validates the record, every device certificate
  and the content signature at the profile's `notBefore`; BlahDiem validates its kind
  and application fields. Invalid signatures or structure reject with the native error
  code (for example `invalidSignature` or `invalidProfile`).
  The returned `ProfileInfo` contains `id` (lowercase hex), `kind`, `generation`,
  `revision`, `notBefore`, `expiresAt`, `lapsed`, ordered `domains`, and nullable
  `home: {dc, account, epoch}`. Home `dc` is the DC identity/federation key ID in hex;
  `account` is null until allocated. All returned integers are decimal strings.
  `lapsed` is true when `now < notBefore` or `now >= expiresAt`; such profiles still
  verify because the server returns its latest stored profile even after expiry.
  A DC's home is itself, account `777000`, epoch `1`. Hosted profiles may have no home.
  This is a stateless check: callers bind the result to the expected identity and
  retain monotonic generation/revision floors. Listed domains are signed claims,
  not proof of current domain control; `lapsed` describes the profile window only.
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

## Profile hosting

`hosting.policy(domain, transport?)` reads a host’s limits and PoW policy.
`hosting.plan(domain, labels, identity, transport?)` returns `invalid`, `taken`, `held`
or `needsProof` names, with the difficulty and puzzle for new names. Pass the lowercase
hex identity ID. Held names are unverified discovery hints; publication decides ownership.

`hosting.solve(puzzle, {signal, start, stride, onProgress}?)` searches eight-byte counters
and yields between batches. `onProgress` reports cumulative attempts; difficulty describes
expected work, not a completion time. Applications can inject their own solver or distribute
counter strides among workers. Cancellation rejects with `type: 'cancelled'`.

Use `identityOperation`’s `create` or `domains` to sign the desired names, then persist
that revision before `hosting.publish(domain, profile, {proofs, solver, transport, via}?)`.
Proofs map labels to nonce bytes and are sent as given for the host to check; a solver
answers one `proof-required` refusal, its nonces checked natively, and publication retries once. Publication accepts any Diem profile kind and returns the identity in
hex, revision as a decimal string and hosted domains in signed order. Retry an unanswered
PUT with the same saved bytes. `via` selects the name host, including a formerly held name
for a full release; a completed full release may not be repeatable at that old name.

`hosting.fetchTransport({signal, timeout}?)` defaults to a 15-second timeout, refuses
redirects, omits credentials and referrers, disables caching and caps streamed responses at
262,144 bytes. Custom transports and solvers return promises; their errors propagate unchanged
(including `AbortError`). They must settle on cancellation so Swift can finish the operation.
Host refusals have `type: 'hostingProblem'`, wire `code`, `status`, `detail`, `labels` and
nullable `retryAfter` seconds. Client failures have a stable `type`; see `diem.d.ts`.

## Recovery words and custody

`seeds.generate()` returns `{words, entropy}`: 24 BIP 39 English recovery words and their
32-byte root. `seeds.restore(phrase)` returns the entropy, ignoring ASCII case and
whitespace and rejecting unknown words, a bad word count or checksum.
`seeds.words(entropy)` shows those words again. Words are the only backup; applications
show and verify them during creation and require device authentication or an explicit
confirmation before showing them again.

`await seeds.identity(entropy, identityPublicKey?)` derives Ed25519 with WebCrypto HKDF-SHA256, optionally
checks the expected Diem identity encoding, then returns `{publicKey, id, signer}`.
`publicKey` is Diem's encoded identity key, `id` is its lowercase hex digest, and `signer`
is a non-extractable Ed25519 CryptoKey. The word codec and public-key computation run in
JavaScript; entropy never enters the client's WASM instance. Intermediate buffers are cleared. Callers
clear entropy buffers when their operation ends.

`await deviceKeys.generate()` returns `{privateKey, publicKey}`. The private CryptoKey
is generated as ECDSA P-256 with `extractable:false` and `usages:['sign']`; the public
key is raw 65-byte SEC1. Persist the CryptoKey object in IndexedDB by structured clone.
Never export or serialize device private keys. A device key serves exactly one session.
WebCrypto custody is `KeyProtection.nonExportable`, without a hardware guarantee.

Store each account slot's seed encrypted with AES-GCM under a separate non-extractable
CryptoKey kept in IndexedDB. Use a new 12-byte random IV for each encryption. Applications
own storage transactions, local deletion, optional app passcode locking and user consent.
Logout deletes that slot's device CryptoKey and encrypted seed. Discard replaced custody
and log out accounts bound to it; there is no legacy decoding or migration.

The `identityOperation` callbacks return raw Ed25519 identity public bytes (32 bytes)
and SEC1 P-256 device public bytes (65 bytes). Sign identity messages with Ed25519 and
device messages with `subtle.sign({name:'ECDSA',hash:'SHA-256'}, privateKey, message)`.
The device signature is the WebCrypto fixed-width 64-byte r‖s result. Verification
callbacks choose the algorithm from the public-key length. A device-only backend returns
an empty identity public key. Each operation retains its own callbacks.

```js
const {words, entropy} = diem.seeds.generate();
const identity = await diem.seeds.identity(entropy);
const device = await diem.deviceKeys.generate();
const backend = {
  random: n => crypto.getRandomValues(new Uint8Array(n)),
  publicKey: role => role === 'identity' ? identity.publicKey.slice(-32) : device.publicKey,
  sign: async(role, bytes) => new Uint8Array(await crypto.subtle.sign(
    role === 'identity' ? 'Ed25519' : {name:'ECDSA', hash:'SHA-256'},
    role === 'identity' ? identity.signer : device.privateKey, new Uint8Array(bytes))),
  verify: verifyRawPublicKey
};
```

Recovery-word sign-in fetches the current trusted profile, checks it with `verifyProfile`,
derives `seeds.identity(entropy, expectedIdentityPublicKey)`, generates a fresh device,
and uses `identityOperation` with `operation:'enroll'`. Enrollment verifies the existing
profile and identity, preserves its devices and signed revision chain, and certifies the
fresh device. Persist custody and publish the returned revision before proving login.

## QR device linking

`deviceLink.begin(label)` returns `{request, parameter, session}`. Send only `request`
to the DC and put `parameter` in the QR URL's `blah` parameter. Labels are untrusted
1–64 UTF-8 bytes. Each session generates a non-extractable P-256 device and an ephemeral
P-256 HPKE recipient. Window and dedicated-worker callers use a disposable module worker
for each link session and approval. SharedWorker cannot spawn a worker; it uses a separate
WASM instance whose full linear memory is wiped before release, after any in-flight operation
settles. Plaintext transfer seeds never enter the client's long-lived WASM instance.
Vendor `device-link-worker.js` beside `diem.js` and allow module workers under the
Content Security Policy described below. Call `session.destroy()` on cancellation.

The seed-holding approver calls `deviceLink.inspect(parameter, request)`, checks both
verification algorithms (identity Ed25519 = 1, device P-256 = 2), certifies `device`,
saves the new profile, and publishes its exact bytes before approving:

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
bytes, at most 16 KiB, allowed only with seed transfer. `respond` checks the QR digest,
capabilities, current published authority and any transferred seed's identity binding.
The library cannot prove remote publication; callers own publication and consent.
`open` checks the expected DC's 32-byte identity, allocated account, listed domain,
current device certification and optional seed binding. Success or failure ends the
session. The returned device is a CryptoKey handle; no device secret crosses the API.
Persist the device and optional encrypted seed before completing sign-in. The QR secret
never goes to the DC, which receives ciphertext only. Native wire rules are in
`DeviceAuthority.md`.

## Vendoring a release

Each successful `main` push publishes a GitHub release named `YYYYMMDD-<sha4>`.
Download a specific release and verify `SHA256SUMS`. Vendor its matching
`diem.js`, `device-link-worker.js`, `diem.wasm`, declarations and license files together; retain the release
tag and `manifest.json` with the checksums and source revision.

Serve WASM as `application/wasm`. Supply an explicit WASM URL when relocating the
assets. The `.br` and `.gz` files require the corresponding `Content-Encoding`.
Consumers need no Swift toolchain or external runtime downloads.

When the runtime is served from another origin, device linking uses a disposable
`blob:` module worker that imports the absolute worker asset URL. Content Security
Policy must allow `worker-src blob:` as well as the runtime origin in `script-src`
and the WASM origin in `connect-src`; CDN assets require CORS headers. The blob URL
is revoked after the worker responds or when it is destroyed. Same-origin workers
and the isolated SharedWorker fallback keep their existing loading paths.

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
override applies to each requested browser; select one engine when overriding).
Build output is in `Web/dist/`. The build pins dependencies, generates BridgeJS
bindings, minimizes the Embedded Swift binary and enforces artifact size limits.
Tests run real WebCrypto operations in Window, DedicatedWorker and SharedWorker under
Chromium and WebKit: recovery words, non-extractable P-256 signatures, IndexedDB CryptoKey
custody, seed transfer and native/browser HPKE interoperability. The supplied
Linux WPE runtime can fail CryptoKey persistence or Ed25519 imports in worker scenarios;
macOS CI checks Safari's native backend.
The [release workflow](../.github/workflows/web-release.yml) owns CI tool installation,
testing and packaging.
