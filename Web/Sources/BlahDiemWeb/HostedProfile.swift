import BlahDiem

// Retain each native profile's validation and name rules when changing its home.
struct HostedProfile {
  let kind: String
  var home: Home?
  var domains: [DomainName]
  private var dc: DCProfile.Content?
  private var dcHome: Home?

  init(kind: String, home: Home?, domains: [DomainName]) {
    self.kind = kind
    self.home = home
    self.domains = domains
  }

  init(_ profile: AnyBlahProfile, kind: String) throws {
    self.kind = kind
    home = profile.home
    domains = profile.domains
    switch profile {
    case .user where kind == "user", .channel where kind == "channel", .bot where kind == "bot",
      .stickerSet where kind == "stickerSet":
      break
    case .dc(let p) where kind == "user" || kind == "dc":
      dcHome = home
      dc = p.content
    default: throw BlahError.invalidProfile
    }
  }

  var content: AnyBlahProfile.Content {
    get throws {
      if var dc {
        guard home?.dc == dcHome?.dc, home?.epoch == dcHome?.epoch,
          home?.account == DCProfile.accountID else { throw BlahError.wrongHome }
        dc.domains = domains
        return .dc(dc)
      }
      switch kind {
      case "user": return .user(HostedContent(home: home, domains: domains))
      case "channel": return .channel(HostedContent(home: home, domains: domains))
      case "bot": return .bot(HostedContent(home: home, domains: domains))
      case "stickerSet":
        guard domains.count == 1 else { throw BlahError.invalidName }
        return .stickerSet(.init(home: home, shortName: domains[0]))
      default: throw BlahError.invalidProfile
      }
    }
  }
}
