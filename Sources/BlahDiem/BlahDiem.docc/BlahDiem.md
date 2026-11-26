# ``BlahDiem``

Blah profiles and proofs on Diem identities, shared by Blah clients and DCs.

## Overview

Every Blah account, bot, channel, sticker set, DC and application is a Diem identity. Each Blah
profile type is a Diem `DomainNamedProfile` whose fields sit under Blah's application ID,
`com.blahim`, and its devices sign the DC's challenges as Blah proofs.

```swift
var user = HostedContent(home: Home(dc: dc.id, epoch: 1, expiresAt: expiry), domains: domains)
let seed = try IdentitySeed.generate(using: backend)
var identity = try await BasicIdentity<UserProfile>(user,
  identityKey: seed.identityKey(.ed25519, using: backend), deviceKey: device, using: backend)
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
- ``ApplicationProfile``
- ``ApplicationWirePair``
- ``AnyBlahProfile``
- ``AnyBlahProfile/content(_:replacingDomains:)``
- ``AnyBlahProfile/Content/replacingDomains(_:)``
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

### Application fields

- ``ApplicationID/blah``

### Device linking

- ``DeviceLinkRequest``
- ``DeviceLinkCode``
- ``DeviceLinkGrant``
- ``DeviceLinkContext``
- ``DeviceLinkResponse``

### Errors

- ``BlahError``
