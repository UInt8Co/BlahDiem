# Identities, profiles and proofs

How Blah uses Diem identities.

## Identities

An identity is an identity key. It certifies device keys; the certificates of one
generation are the identity's current devices, and removing a device starts a new
generation. The publisher chooses profile and certificate lifetimes; a profile cannot
outlive its signing certificate. DC browser setup defaults both to 90 days and lets the
operator choose each period. Ordinary identity creation retains Diem's one-day profile
and 30-day certificate defaults.

An identity derives from an `IdentitySeed`: 32 entropy bytes shown as 24 recovery words.
Seed holders derive the identity key to manage devices. The seed moves between holders
as a `SealedIdentitySeed`, encrypted to the receiving device's encryption key. Applications
store it encrypted at rest. Recovery words are the only backup.

## Keys

Each key serves one purpose. The identity key only certifies devices; a device key signs
profile content and every Blah proof; an encryption key receives HPKE-sealed secrets.
A DC's ``DCProfile/transportPublicKey`` is a separate RSA key for MTProto key exchange,
never a Diem key, and is not post-quantum.

Diem's generic signing default remains ML-DSA-65. Blah clients explicitly derive Ed25519
identities and generate P-256 devices: Secure Enclave on iOS, non-extractable WebCrypto
on the web. WebCrypto keys use `KeyProtection.nonExportable`, which makes no hardware
guarantee. Device private keys are never exported or transferred. Applications persist
platform key references or CryptoKey objects. Each device key serves one session.

## Wire

Diem owns every integer key of its records. Blah's application ID is `com.blahim`
(``ApplicationID/blah``), and Blah writes exactly two Diem fields under it:

- **Profile content**: Diem's keys 0–9 (9 holds the domains) and `"com.blahim"`, a map
  of Blah's integer keys. Key 0 is the profile kind (1 user, 2 channel, 3 bot,
  4 sticker set, 5 DC, 6 application). User, bot, channel and sticker-set maps hold the
  ``Home`` or null at key 1. A DC map holds client endpoints at 2, BIDCOM endpoints at 3,
  the transport key at 4 and the namespace generation at 5; an application map holds the
  name at 2, download URL 3, bot 4, OAuth 5, push 6 and versions 7. Each type's
  `cborKey…` constants name these keys inside the map.
- **Proofs**: the proof's `"com.blahim"` value is the signed statement's record, so a
  ``BlahProof``'s `statement.encoding` is exactly the bytes the DC issued.

Decoders ignore unknown keys inside Blah's map, and publishing Blah content replaces the
whole map: `Identity.updating` signs only what the content holds. Other applications'
fields and newer Diem keys are kept, as Diem's publishing rules require, and renewing or
changing devices re-signs everything verbatim.

Blah's own records — the challenges and statements, ``InvocationChallenge`` and
``ClientNamespace`` — are canonical CBOR maps with a fixed numeric tag at key 0 and
version 1 at key 1, and expose their field numbers as `cborKey…` constants. Decoders
validate required fields and keep unknown integer keys and application fields, so a
statement re-encodes to the bytes it was decoded from. Tags 14–20 are retired and never
reused; device-link records are Diem's.

## Linking another device

Blah links devices with Diem's QR device linking; see
[Linking a device](https://github.com/UInt8Co/diem/blob/main/Sources/Diem/Diem.docc/Diem.md#linking-a-device)
for the records, the code's binding and the checks Diem makes. Blah adds its own rules:

- The code travels in the QR URL's `blah` parameter. Cross-platform identities use
  Ed25519 explicitly; the new device's key is a non-exportable P-256 key.
- The approving device saves and publishes the revision certifying the new device
  through its existing profile publisher before sending a response. The DC learns the
  revision through its normal profile fetch. Linking cannot allocate an account.
- A grant is accepted only for a user profile whose ``Home`` is active, has an allocated
  account and, when opening, is the DC the new device expects. Opening without an
  expected DC is ``BlahError/wrongHome``: a response cannot establish which DC the client
  meant to connect to.
- Blah's opaque `metadata`, at most 16,384 bytes, travels as bytes in the grant's
  `com.blahim` field, only with seed transfer, and carries no authority.

``DeviceLinkResponse/seal(_:for:code:using:)`` and
``DeviceLinkResponse/open(_:recipientKey:request:code:expectedDC:at:using:)`` apply
these rules to Diem's `seal` and `open` with ``AnyBlahProfile``; ``DeviceLinkGrant``
carries the metadata. Any opening failure ends the
link session. After success the caller stores custody before completing sign-in with a
proof from the new device; account password checks still apply. The web package's README
describes its opaque session and custody API.

## Profiles

Each Blah profile type conforms to ``BlahProfile``, a Diem `DomainNamedProfile` that
owns the `com.blahim` field. Its fields are signed directly in the Diem profile content:
the domains that serve it in Diem's standard domains field, and its kind and that kind's
fields in Blah's map (see <doc:DeviceAuthority#Wire>). Each type decodes only its own
kind; ``AnyBlahProfile`` decodes any. A type's `Content` is what the publisher edits, and
`BasicIdentity` signs it as the next revision.

Use Diem's `init(verifying:using:)` for public profiles returned by a DC, such as
`AnyBlahProfile(verifying:using:)`. It decodes Blah's fields and verifies at the
profile's `notBefore`, so a stored profile can still verify after expiry. Check `profile.validity.contains(now)`
to determine whether its window is current. This performs no domain binding; callers
pin the expected identity and retain monotonic generation/revision floors.

A hosted identity names its ``Home``: the DC's identity ID, the epoch of the hosting
and, once allocated, the account number. A later epoch is a new account. Every domain
of a user, bot or channel profile is a public username candidate; a sticker set has
exactly one, its short name. Verification and activation belong to the home DC.

A ``DCProfile`` advertises client and BIDCOM endpoints, the RSA transport key and
database namespace generation, and at least one discovery domain. It also represents a
special user account, permanently hosted by its own identity as account 777000 in epoch
1. The signed profile supplies that identity and the hosting's expiry; no independent
home can move it elsewhere. ``BlahProfile/home`` is the common hosting view used by
proofs and client namespaces. Endpoints use integer-keyed maps: transport 0 is TCP
with a null path; transport 1 is WebSocket with an absolute HTTP path, optionally
including a query. TLS is explicit for either transport. The endpoint lists are bounded
and contain no duplicates; BIDCOM accepts TCP only and can be empty. Clients verify the
profile and that it serves its discovery domain before using these values. The field
keys and validation belong to each profile type.

An ``ApplicationProfile`` describes client software that connects to any DC. It has
no home. Its first domain names it to DCs and OAuth. It carries a display name and
optionally a download URL, a bot (the bot's identity and its home DC's identity), OAuth
client data (public-client flag, exact redirect URIs and `private_key_jwt` keys for
`EdDSA` or `ES256`), push proxy endpoints (an HTTPS credentials URL, APNs topic and
production and sandbox proxies, a Web Push proxy and VAPID public key) and enabled
versions. The versions are strictly increasing boundaries. Each one starts a range that
runs up to the next. The ranges alternate between enabled and disabled, starting
enabled, so versions below the first boundary are disabled. An absent list enables every
version and an empty list enables none; see
``ApplicationProfile/Content/isEnabled(version:)``. ``ApplicationWirePair`` derives
the MTProto `api_id` and `api_hash` from the identity ID. Neither value is secret.
Derived IDs start at `0x40000000`, above DC-local legacy IDs.

## Profile hosting

BlahDiem re-exports `DiemProfileHostingClient`. Supply its HTTP transport and solver.
Each profile type's `content(_:replacingDomains:)`, such as
``AnyBlahProfile/content(_:replacingDomains:)``, preserves the profile kind and all
other fields when Diem's hosting client prepares a claim or release:

```swift
let claim = try await identity.claiming(labels: ["alice"], at: host, solver: solver)
// Store the signed revision before publication; retry unanswered PUTs with these bytes.
try await host.publish(claim, solver: solver)
```

`identity.releasing(labels:at:)` works the same way. Users, bots
and channels may have no domains; a DC must retain at least one discovery domain.
A sticker set requires exactly one: replace its short name with `identity.updating`
instead of appending another name or removing its last name. A full release through
a formerly held name may not be repeatable after success; callers reconcile that
case separately. Planning is only a discovery hint; the host decides ownership.

## Proofs

A DC issues a ``BlahStatement`` — a login, invocation or approval challenge, a Diem
`Statement` of `com.blahim` — and a device signs it with `Identity.prove(_:)`, which
returns a ``BlahProof``, Diem's `StatementProof`. Before signing, Blah's `prove` checks
that the statement is live (it expires within 120 seconds, else
``BlahError/challengeExpired``), from the identity's home and for this identity and
device. An approval is
signed only when it equals what the user reviewed. The DC verifies the ``BlahProof``
against the identity's current profile.
