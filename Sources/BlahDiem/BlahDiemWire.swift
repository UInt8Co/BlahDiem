/// Numeric tags for Blah payloads embedded in Diem signed records or used as
/// canonical local identifiers. Array positions following a tag are fixed field
/// numbers; decoders require the exact record length and canonical CBOR.
public enum BlahDiemTag: UInt64, Sendable {
  case reference = 1
  case references = 2
  case login = 3
  case identityChallenge = 4
  case identityInvocation = 5
  case oauthConsent = 6
  case credentialAuthority = 7
  case accountLink = 8
  case dcAdmin = 9
  case clientNamespace = 10
  case bidcomBind = 11
  case bidcomAccept = 12
}

/// Keys in the Diem profile's application fields map.
public enum BlahProfileField: UInt64, Sendable {
  case home = 0
  case domains = 1
  case dc = 2
}

enum BlahReferenceTag: UInt64 {
  case identity = 1, authority = 2, object = 3, conversation = 4, event = 5, authorization = 6
}

extension HomeDelegation.Kind {
  var wireCode: UInt64 {
    switch self {
    case .user: 1
    case .channel: 2
    case .bot: 3
    case .stickerSet: 4
    }
  }
  init?(wireCode: UInt64) {
    switch wireCode {
    case 1: self = .user
    case 2: self = .channel
    case 3: self = .bot
    case 4: self = .stickerSet
    default: return nil
    }
  }
}

extension LocalIDKind {
  var wireCode: UInt64 {
    switch self {
    case .user: 1
    case .chat: 2
    case .monoforum: 3
    case .file: 4
    case .stickerSet: 5
    case .poll: 6
    case .topic: 7
    case .message: 8
    case .dc: 9
    case .authorization: 10
    }
  }
  init?(wireCode: UInt64) {
    switch wireCode {
    case 1: self = .user
    case 2: self = .chat
    case 3: self = .monoforum
    case 4: self = .file
    case 5: self = .stickerSet
    case 6: self = .poll
    case 7: self = .topic
    case 8: self = .message
    case 9: self = .dc
    case 10: self = .authorization
    default: return nil
    }
  }
}

extension DeviceLoginChallenge.Operation {
  var wireCode: UInt64 { self == .signUp ? 1 : 2 }
  init?(wireCode: UInt64) {
    switch wireCode {
    case 1: self = .signUp
    case 2: self = .signIn
    default: return nil
    }
  }
}

extension AccountLinkChallenge.Operation {
  var wireCode: UInt64 {
    switch self {
    case .read: 1
    case .start: 2
    case .confirm: 3
    case .unlink: 4
    }
  }
  init?(wireCode: UInt64) {
    switch wireCode {
    case 1: self = .read
    case 2: self = .start
    case 3: self = .confirm
    case 4: self = .unlink
    default: return nil
    }
  }
}

extension DCAdminChallenge.Operation {
  var wireCode: UInt64 {
    switch self {
    case .read: 1
    case .replace: 2
    case .linkBot: 3
    }
  }
  init?(wireCode: UInt64) {
    switch wireCode {
    case 1: self = .read
    case 2: self = .replace
    case 3: self = .linkBot
    default: return nil
    }
  }
}
