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
Wire tags 14–16 are retired and never reused.

## Linking another device

The new device creates a non-exportable P-256 signing key and a fresh P-256 encryption key. Its
``DeviceLinkRequest`` goes to the DC; its ``DeviceLinkCode`` travels only in the QR
code's `blah` parameter. The approving device checks `DeviceLinkCode.matches(_:)`
against the received bytes before decoding the request, then checks that the new
device can verify both its identity and device signing algorithms before certifying it.
Labels are untrusted display text. Cross-platform identities use Ed25519 explicitly;
native creation continues to default to ML-DSA-65.

Approval certifies the new signing key in the identity's current generation. The
approving device saves and publishes that signed revision through its existing profile
publisher before sending a response. The DC learns the revision through its normal
profile fetch, independently of profile hosting. Linking cannot allocate an account.

``DeviceLinkGrant`` carries those exact published bytes, a listed domain, and optionally
a Diem `SealedIdentitySeed` at key 4 for the new device. Opaque application metadata is allowed only
with seed transfer, and carries no authority. ``DeviceLinkContext`` binds the response
to the request digest and QR secret as both HPKE info and associated data. The secret
never goes to the DC. Opening requires a live user profile, an active home at the expected
DC with an allocated account, a listed domain, and certification of the requested device
in the current generation. Opening re-derives the profile's identity from the transferred seed.

Any opening failure ends the link session. After success the caller stores custody
before completing sign-in with a proof from the new device. Account password checks still
apply. `DeviceLinkResponse.Opened.seed` is optional; the device key stays in its platform store.
The web package's README describes its opaque session and custody API.

## Profiles

Each Blah profile type conforms to ``BlahProfile``, a Diem `DomainNamedProfile`. Its
fields are signed directly in the Diem profile content: the domains that serve it in
Diem's standard domains field, and from Diem's first application key a profile kind
followed by that kind's fields. Each type decodes only its own kind;
``AnyBlahProfile`` decodes any. A type's `Content` is what the publisher edits, and
`BasicIdentity` signs it as the next revision.

Use ``AnyBlahProfile/init(verifying:using:)`` for public profiles returned by a DC.
It decodes Blah's fields and calls Diem's verification at the profile's `notBefore`,
so a stored profile can still verify after expiry. Check `profile.validity.contains(now)`
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

## Profile hosting

BlahDiem re-exports `DiemProfileHostingClient`. Supply its HTTP transport and solver;
use ``AnyBlahProfile/Content/replacingDomains(_:)`` to preserve the profile kind and
all other fields when preparing a claim or release:

```swift
let claim = try await identity.claiming(labels: ["alice"], at: host, solver: solver) {
  try $0.replacingDomains($1)
}
// Store the signed revision before publication; retry unanswered PUTs with these bytes.
try await host.publish(claim, solver: solver)
```

The same transform works with `identity.releasing(labels:at:transform:)`. Users, bots
and channels may have no domains; a DC must retain at least one discovery domain.
A sticker set requires exactly one: replace its short name with `identity.updating`
instead of appending another name or removing its last name. A full release through
a formerly held name may not be repeatable after success; callers reconcile that
case separately. Planning is only a discovery hint; the host decides ownership.

## Proofs

A DC issues a ``BlahStatement`` — a login, invocation or approval challenge — and a device
signs it with `Identity.prove(_:)`, which returns a ``BlahProof``, a Diem `Proof`. Before signing, the statement checks
that it is live, from the identity's home and for this identity and device. An approval is
signed only when it equals what the user reviewed. The DC verifies the ``BlahProof``
against the identity's current profile.
