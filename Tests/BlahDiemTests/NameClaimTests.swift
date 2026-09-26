import BlahDiem
import Foundation
import Testing

/// A signed profile advertises the domains that host it and flags the public names.
@Suite struct NameClaimTests {
  static let now: UInt64 = 1_800_000_000
  static let key = [UInt8](repeating: 7, count: 32)

  @Test func aProfileCarriesItsNameBesideTheHomeAndKeepsItAcrossRenumbering() throws {
    let device = try DeviceSigner(
      signingKey: SoftwareSigningKey(algorithm: .ed25519), wrappingKey: SoftwareWrappingKey(algorithm: .x25519))
    let home = try HomeDelegation(domain: "one.example", federationKeyID: Self.key, epoch: 1,
      expiresAt: Self.now + 3600).claiming(name: "alice.one.example")
    let profile = try IdentityController.create(on: device, fields: home.fields, at: Self.now).profile
    let parsed = try HomeDelegation(profile: profile, at: Self.now)
    #expect(parsed.name == "alice.one.example" && parsed.kind == .user)
    #expect(try parsed.naming(account: 1_000_001).name == "alice.one.example")
    #expect(try parsed.claiming(name: nil).fields != parsed.fields)
    // An unnamed profile retains the domain list, even when it is empty.
    let unnamed = try parsed.claiming(name: nil)
    guard case .map(let pairs) = unnamed.fields else { throw FederationError.invalidDelegation }
    #expect(pairs.count == 2)
  }

  @Test func namesAreDomainsAndABotsFirstLabelEndsInBot() throws {
    for name in ["alice", "Alice.example", "ali_ce.example", "-a.example", "a..example", "a.example."] {
      #expect(throws: FederationError.invalidName) {
        try HomeDelegation(domain: "one.example", federationKeyID: Self.key, epoch: 1,
          expiresAt: Self.now + 3600, name: name)
      }
    }
    #expect(throws: FederationError.invalidName) {
      try HomeDelegation(kind: .bot, domain: "one.example", federationKeyID: Self.key, epoch: 1,
        expiresAt: Self.now + 3600, account: 1_000_002, name: "helper.one.example")
    }
    let bot = try HomeDelegation(kind: .bot, domain: "one.example", federationKeyID: Self.key, epoch: 1,
      expiresAt: Self.now + 3600, account: 1_000_002, name: "helperbot.one.example")
    #expect(bot.name == "helperbot.one.example")
    // A resource's number comes from its own local space.
    #expect(throws: FederationError.invalidDelegation) {
      try HomeDelegation(kind: .channel, domain: "one.example", federationKeyID: Self.key, epoch: 1,
        expiresAt: Self.now + 3600, account: LocalIDKind.chat.upperBound)
    }
    #expect(try CanonicalReference.identity(Self.key, kind: .bot, epoch: 1).kind == .user)
    #expect(try CanonicalReference.identity(Self.key, kind: .stickerSet, epoch: 1).kind == .stickerSet)
    #expect(DomainName.name("alice.one.example", isBelow: "one.example"))
    #expect(!DomainName.name("one.example", isBelow: "one.example"))
    #expect(!DomainName.name("aliceone.example", isBelow: "one.example"))
  }

  @Test func aProfileAdvertisesSeveralDomainsAndFlagsOnlyPublicNames() throws {
    let domains = try [ProfileDomain("alice.example", username: true),
      ProfileDomain("id.example"), ProfileDomain("alice.other.example", username: true)]
    let home = try HomeDelegation(domain: "one.example", federationKeyID: Self.key, epoch: 1,
      expiresAt: Self.now + 3600, domains: domains)
    let device = try DeviceSigner(signingKey: SoftwareSigningKey(algorithm: .ed25519),
      wrappingKey: SoftwareWrappingKey(algorithm: .x25519))
    let signed = try IdentityController.create(on: device, fields: home.fields, at: Self.now).profile
    let parsed = try HomeDelegation(profile: signed, at: Self.now)
    #expect(parsed == home)
    #expect(parsed.names("alice.example") && parsed.names("alice.other.example"))
    #expect(parsed.advertises("id.example") && !parsed.names("id.example"))
    #expect(!parsed.advertises("impostor.example"))
    #expect(throws: FederationError.invalidName) {
      try home.advertising([domains[0], domains[0]])
    }
  }
}
