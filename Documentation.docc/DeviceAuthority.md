# Device authority

BlahDiem's device authority uses Diem v2 records to separate an identity's root authority
from ordinary device use. The identity
is the SHA-256 identifier of its algorithm-qualified identity public key. The identity
key signs only a device list. A listed device signs a profile and application proofs.
`DiemPortable` supplies canonical CBOR and key contracts. BlahDiem owns the device
roster, profile, enrollment and proof records, along with their authority checks.
Platform cryptography lives in `DiemSwiftCrypto`. Applications own private key custody
and profile publication.

`DeviceSigner` holds separate opaque signing and wrapping operations. Ed25519 and
P-256 signing can independently pair with X25519 or P-256 wrapping. ML-DSA-65 signing
and X-Wing wrapping are explicitly selectable software algorithms on supported
platforms. P-256 public keys use uncompressed SEC1 encoding; signatures use 64-byte
IEEE P1363 encoding over
SHA-256. Wrapping uses RFC 9180 base-mode HPKE with SHA-256 and either
X25519/ChaCha20-Poly1305 or P-256/AES-256-GCM. The envelope context binds the identity,
both recipient keys and version as both HPKE info and AEAD associated data.
The record encodings are owned by `Sources/BlahDiem/`.

## Controllers and enrollment

`IdentityController.create` generates the root transiently, signs the initial list,
encrypts the root to the first controller and returns only the profile and encrypted
envelope. Ordinary enrollment returns no envelope. A new device proves possession
of its signing key and decrypts a fresh challenge to prove possession of its wrapping
key. The approving device must compare the enrollment digest through verified pairing;
receiving it from a relay is insufficient. Controller promotion is an explicit separate
grant. Public profiles contain neither private handles nor encrypted root envelopes.

A controller can retain a decrypted root forever. Removing its device entry stops
ordinary device use once the new roster is learned, but cannot revoke its knowledge
of that root. Controller promotion is permanent root trust. Root compromise requires
a new identity. Losing every controller envelope leaves listed ordinary devices able
to sign profiles until the roster expires, but unable to change or renew that roster.

Software keys report software protection. Secure Enclave keys are generated on the
destination Apple device and persist as device-bound opaque references. Secure Enclave
tests require a real supported device; Linux tests do not validate hardware custody.
The Android Keystore integration lives in Diem's `Android/` directory. Its independent
HPKE verifier lives in this package's `Scripts/` directory. Applications own key
persistence; opaque platform references are never disguised as exported private key bytes.

## Verified history

`ProfileAuthorityState` validates signed bytes before replacing its head. Applications
persist its roster and profile version floors and any historical statements they need.
A new roster invalidates every older profile branch even without a replacement profile.
Within one roster, profile revisions order statements; same-version forks are reported
as conflicts. Cooperative writers can require a previous digest with compare-and-swap.
Statement digests cover exact signed payload bytes rather than nondeterministic ECDSA
signature encodings. Consecutive updates must reference the stored predecessor;
signed revision jumps allow peers to learn updates after missing intermediate versions.

Live authority requires a profile valid for at most one day inside a roster valid for
at most thirty days. These are maximum stale windows, not discovery guarantees.
Applications must consult the current stored head on active use. Historical statements
are evidence, never permission to execute backdated operations. Cached authority floors
must survive cache eviction and process restart.

Encrypt to an explicitly selected certified device. Algorithm selection never silently
changes the recipient device, and signing and wrapping algorithms are independent.
