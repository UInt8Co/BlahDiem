import BlahDiem

// Retain each native profile's validation and name rules when changing its home.
struct HostedProfile {
  let kind: String
  var home: Home?
  var domains: [ProfileDomain]

  init(kind: String, home: Home?, domains: [ProfileDomain]) {
    self.kind = kind
    self.home = home
    self.domains = domains
  }

  init(_ profile: Profile, kind: String) throws {
    self.kind = kind
    switch try AnyBlahProfile(profile) {
    case .user(let p) where kind == "user": home = p.home; domains = p.domains
    case .channel(let p) where kind == "channel": home = p.home; domains = p.domains
    case .bot(let p) where kind == "bot": home = p.home; domains = p.domains
    case .stickerSet(let p) where kind == "stickerSet":
      home = p.home; domains = [try ProfileDomain(p.shortName)]
    default: throw BlahError.invalidProfile
    }
  }

  func encoded() throws -> [UInt8] {
    switch kind {
    case "user": return try UserProfile(home: home, domains: domains).encoded()
    case "channel": return try ChannelProfile(home: home, domains: domains).encoded()
    case "bot": return try BotProfile(home: home, domains: domains).encoded()
    case "stickerSet":
      guard domains.count == 1 else { throw BlahError.invalidName }
      return try StickerSetProfile(home: home, shortName: domains[0].name).encoded()
    default: throw BlahError.invalidProfile
    }
  }
}
