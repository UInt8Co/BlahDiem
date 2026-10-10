# Identities, profiles and proofs

How Blah uses Diem identities.

## Identities

An identity is an identity key. It certifies device keys; the certificates of one
generation are the identity's current devices, and removing a device starts a new
generation. The publisher chooses profile and certificate lifetimes; a profile cannot
outlive its signing certificate. DC browser setup defaults both to 90 days and lets the
operator choose each period. Ordinary identity creation retains Diem's one-day profile
and 30-day certificate defaults.

The identity key stays on the devices that manage the device set. It moves between them
as a `SealedIdentityKey`, sealed to the receiving device's encryption key, and is
stored the same way, sealed to a key the device holds.

## Keys

Each key serves one purpose. The identity key only certifies devices; a device key signs
profile content and every Blah proof; an encryption key receives HPKE-sealed secrets.
A DC's ``DCProfile/transportPublicKey`` is a separate RSA key for MTProto key exchange,
never a Diem key, and is not post-quantum.

New identities use ML-DSA-65 keys, and device-addressed identity transfer defaults to
X-Wing unless the caller chooses otherwise. The browser runtime creates Ed25519
software keys and verifies Ed25519 and P-256 profiles.

## Password-protected key files

``KeyFile`` is the common canonical-CBOR storage and export format for browser custody,
DC setup and native file recovery. ``KeyFileContents`` holds the signed profile, one
identity key, one listed device key, or both, and an encrypted application metadata map.
The key roles remain distinct: a device-only file grants no recovery authority. A Diem
`PaperDeviceKey` is a listed software device written as 24 words; custody that keeps it
uses a device-only file. Native
hardware device keys stay on their device; native recovery exports the software identity
key and enrolls a new hardware device when restored.

Version one uses exact UTF-8 password bytes, a random 16-byte salt and
PBKDF2-HMAC-SHA256 with 600,000 iterations to produce the input to RFC 9180's P-256
`DeriveKeyPair`. The resulting recipient opens Diem's P-256/HKDF-SHA256/AES-256-GCM
base-mode HPKE box. The entire header, including extensions, is both HPKE info and
associated data. Passwords must be nonempty; there are no other length or complexity
requirements. Neither passwords nor recipient private keys are stored in the file.

The file authenticates its identity, key purposes and signed profile, and checks that
private keys reproduce the declared public keys. Restoring an expired signed profile is
allowed for recovery; current published authority is still required for authentication.
File decoding and KDF work are bounded. JSON files are not accepted. Field numbers,
size limits and the native API belong to ``KeyFile`` and ``KeyFileContents``; the web
adapter and custody session API are described in the web package's README.

## Profiles

Each Blah profile type conforms to ``BlahProfile``, a Diem `DomainNamedProfile`. Its
fields are signed directly in the Diem profile content: the domains that serve it in
Diem's standard domains field, and from Diem's first application key a profile kind
followed by that kind's fields. Each type decodes only its own kind;
``AnyBlahProfile`` decodes any. A type's `Content` is what the publisher edits, and
`BasicIdentity` signs it as the next revision.

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

## Proofs

A DC issues a ``BlahStatement`` — a login, invocation or approval challenge — and a device
signs it with `Identity.prove(_:)`, which returns a ``BlahProof``, a Diem `Proof`. Before signing, the statement checks
that it is live, from the identity's home and for this identity and device. An approval is
signed only when it equals what the user reviewed. The DC verifies the ``BlahProof``
against the identity's current profile.
