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
profile content and every Blah proof; an encryption key only receives sealed identity keys.
A DC's ``DCProfile/transportPublicKey`` is a separate RSA key for MTProto key exchange,
never a Diem key, and is not post-quantum.

New identities use ML-DSA-65 keys, and identity keys are sealed to X-Wing encryption keys,
unless the caller chooses otherwise. Web clients target evergreen browsers: WebCrypto supplies SHA-2, HKDF,
AES-256-GCM and X25519, and the client supplies ML-DSA-65 and ML-KEM-768 wherever
WebCrypto lacks them.

## Profiles

A `Profile` carries a ``BlahProfile`` as its data. A hosted identity names its
``Home``: the DC's identity ID, the epoch of the hosting and, once allocated, the account
number. A later epoch is a new account. Its ``ProfileDomain`` list names the domains that
serve the profile; a flagged domain is a public name.

A ``DCProfile`` advertises client and BIDCOM endpoints, the RSA transport key and
database namespace generation. Each endpoint is encoded as
`[host, port, tls, transport, path]`: transport 0 is TCP with a null path; transport 1
is WebSocket with an absolute HTTP path, optionally including a query. TLS is explicit
for either transport. The endpoint lists are bounded and contain no duplicates;
BIDCOM accepts TCP only and can be empty. Clients verify the enclosing Diem profile
and its discovery domain before using these values. This replaces the earlier three-field
endpoint encoding.

## Proofs

A DC issues a ``BlahStatement`` — a login, invocation or approval challenge — and a device
signs it with `Identity.prove(_:)`. Before signing, the statement checks
that it is live, from the identity's home and for this identity and device. An approval is
signed only when it equals what the user reviewed. The DC verifies the ``BlahProof``
against the identity's current profile.
