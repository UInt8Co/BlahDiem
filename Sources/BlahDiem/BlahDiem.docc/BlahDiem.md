# ``BlahDiem``

Blah profiles and proofs on Diem identities, shared by Blah clients and DCs.

## Overview

Every Blah account, bot, channel, sticker set and DC is a Diem identity. Each Blah
profile type is a Diem `DomainNamedProfile`, and its devices sign the DC's challenges as
Blah proofs.

```swift
var user = HostedContent(home: Home(dc: dc.id, epoch: 1, expiresAt: expiry), domains: domains)
var identity = try await BasicIdentity<UserProfile>(user, using: backend)
user.home?.account = accountID
try await identity.update(user)
let proof = try await identity.prove(loginChallenge)
```

## Topics

### Essentials

- <doc:DeviceAuthority>

### Profiles

- ``BlahProfile``
- ``UserProfile``
- ``BotProfile``
- ``ChannelProfile``
- ``StickerSetProfile``
- ``DCProfile``
- ``AnyBlahProfile``
- ``HostedContent``
- ``Home``
- ``DCAddress``

### Proofs

- ``BlahProof``
- ``BlahStatement``
- ``LoginChallenge``
- ``InvocationChallenge``
- ``InvocationStatement``
- ``OAuthConsentChallenge``
- ``AccountLinkChallenge``
- ``DCAdminChallenge``

### Client storage

- ``ClientNamespace``
- ``KeyFile``
- ``KeyFileContents``
- ``KeyFilePrivateKey``

### Errors

- ``BlahError``
