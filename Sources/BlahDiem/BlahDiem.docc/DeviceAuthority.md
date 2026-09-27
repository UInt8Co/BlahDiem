# Identities, profiles and proofs

How Blah uses Diem identities.

## Identities

An identity is an identity key. It certifies device keys; the certificates of one
generation are the identity's current devices, and removing a device starts a new
generation. A certificate lasts at most 30 days and profile content at most one day.

The identity key stays on the devices that manage the device set. It moves between them
as a `SealedIdentityKey`, sealed to the receiving device's encryption key, and is
stored the same way, sealed to a key the device holds.

## Profiles

A `Profile` carries a ``BlahProfile`` as its data. A hosted identity names its
``Home``: the DC's identity ID, the epoch of the hosting and, once allocated, the account
number. A later epoch is a new account. Its ``ProfileDomain`` list names the domains that
serve the profile; a flagged domain is a public name.

## Proofs

A DC issues a ``BlahStatement`` — a login, invocation or approval challenge — and a device
signs it with `Identity.prove(_:)`. Before signing, the statement checks
that it is live, from the identity's home and for this identity and device. An approval is
signed only when it equals what the user reviewed. The DC verifies the ``BlahProof``
against the identity's current profile.
