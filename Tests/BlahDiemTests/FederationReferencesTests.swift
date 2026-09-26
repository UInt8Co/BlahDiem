import BlahDiem
import Foundation
import Testing

@Suite struct FederationReferencesTests {
  @Test func channelAndFileManifestsKeepKindsOwnersAndCanonicalEncoding() throws {
    let origin = try FederationDestination(domain: "one.example", keyID: Array(repeating: 1, count: 32))
    let user = try FederationUserReference(localID: 1_000_000, identity: Array(repeating: 2, count: 32), epoch: 1, publisher: "two.example")
    let binding = try CanonicalReference.object(authority: origin.keyID, kind: .chat, originID: 7, generation: 11)
    #expect(binding.objectOrigin?.id == 7 && binding.objectOrigin?.generation == 11)
    #expect(binding.objectOrigin?.authority == origin.keyID)
    let channel = try FederationChannelReference(localID: 17, canonical: binding, metadata: .init(title: "Group", kindFlags: 2))
    let fileBinding = try CanonicalReference.object(authority: origin.keyID, kind: .file, originID: 7, generation: 11)
    let file = try FederationFileReference(localID: 17, canonical: fileBinding, ownerUserID: user.localID,
      descriptor: .init(kind: "document", mimeType: "application/octet-stream", size: 4096, name: "blob",
        fileReference: Data([1, 2, 3]), width: nil, height: nil, voiceDuration: nil,
        voiceWaveform: nil, roundVideoDuration: nil, documentAttributes: nil))
    let poll = try FederationPollReference(localID: 17, canonical: .object(authority: origin.keyID,
      kind: .poll, originID: 7, generation: 11))
    for files in [[], [file]] {
      for polls in [[], [poll]] {
        let manifest = try FederationReferences(origin: origin, layer: 229, users: [user], channels: [channel], files: files, polls: polls)
        #expect(try FederationReferences.decode(manifest.encoding) == manifest)
        #expect(throws: (any Error).self) { try FederationReferences.decode(manifest.encoding + [0]) }
        for length in 0..<manifest.encoding.count {
          #expect(throws: (any Error).self) { try FederationReferences.decode(Array(manifest.encoding.prefix(length))) }
        }
      }
    }
    for id: Int64 in [0, -1, Int64.max] {
      #expect(throws: FederationError.invalidReference) { try FederationPollReference(localID: id, canonical: poll.canonical) }
    }
    #expect(throws: FederationError.invalidReference) { try FederationPollReference(localID: 17, canonical: fileBinding) }
    #expect(throws: FederationError.invalidReference) {
      try FederationReferences(origin: origin, layer: 229, users: [user], polls: [poll, poll])
    }
    let pollOnly = try FederationReferences(origin: origin, layer: 229, users: [], polls: [poll])
    #expect(try FederationReferences.decode(pollOnly.encoding) == pollOnly)
    #expect(throws: FederationError.invalidReference) {
      try FederationReferences(origin: origin, layer: 229, users: [], channels: [channel], files: [file])
    }
    #expect(throws: FederationError.invalidReference) {
      try FederationReferences(origin: origin, layer: 229, users: [user], channels: [channel, channel])
    }
    #expect(throws: FederationError.invalidReference) {
      try FederationChannelReference(localID: 17, canonical: fileBinding)
    }
    #expect(throws: FederationError.invalidReference) {
      try FederationReferences(origin: origin, layer: 229, users: [user], files: [file, file])
    }
  }

  @Test func stickerSetManifestsBindMembershipToListedSets() throws {
    let origin = try FederationDestination(domain: "one.example", keyID: Array(repeating: 1, count: 32))
    let user = try FederationUserReference(localID: 1_000_000, identity: Array(repeating: 2, count: 32), epoch: 1, publisher: "two.example")
    let setBinding = try CanonicalReference.object(authority: origin.keyID, kind: .stickerSet, originID: 3, generation: 11)
    let set = try FederationStickerSetReference(localID: 9, canonical: setBinding, metadata: .init(emojis: true,
      title: "Emoji", shortName: "pack", count: 1, hash: -5))
    func file(_ setID: Int64?) throws -> FederationFileReference {
      try .init(localID: 17, canonical: .object(authority: origin.keyID, kind: .file, originID: 7, generation: 11),
        ownerUserID: user.localID, descriptor: .init(kind: "document", mimeType: "image/webp", size: 3, name: nil,
          fileReference: Data([1]), width: 512, height: 512, voiceDuration: nil, voiceWaveform: nil,
          roundVideoDuration: nil, documentAttributes: nil, stickerSetID: setID, stickerAlt: setID.map { _ in "⭐" }))
    }
    for files in [[], [try file(9)], [try file(nil)]] {
      let manifest = try FederationReferences(origin: origin, layer: 229, users: [user], files: files, stickerSets: [set])
      #expect(try FederationReferences.decode(manifest.encoding) == manifest)
      for length in 0..<manifest.encoding.count {
        #expect(throws: (any Error).self) { try FederationReferences.decode(Array(manifest.encoding.prefix(length))) }
      }
    }
    #expect(throws: FederationError.invalidReference) {
      try FederationReferences(origin: origin, layer: 229, users: [user], files: [file(10)], stickerSets: [set])
    }
    #expect(throws: FederationError.invalidReference) {
      try FederationReferences(origin: origin, layer: 229, users: [user], stickerSets: [set, set])
    }
    #expect(throws: FederationError.invalidReference) {
      try FederationStickerSetReference(localID: 9, canonical: .object(authority: origin.keyID, kind: .file,
        originID: 3, generation: 11), metadata: set.metadata)
    }
    #expect(throws: FederationError.invalidReference) {
      try FederationFileReference.Descriptor(kind: "photo", mimeType: "image/jpeg", size: 3, name: nil,
        fileReference: Data(), width: nil, height: nil, voiceDuration: nil, voiceWaveform: nil,
        roundVideoDuration: nil, documentAttributes: nil, stickerSetID: 9, stickerAlt: "⭐")
    }
    #expect(throws: FederationError.invalidReference) {
      try FederationFileReference.Descriptor(kind: "document", mimeType: "image/webp", size: 3, name: nil,
        fileReference: Data(), width: nil, height: nil, voiceDuration: nil, voiceWaveform: nil,
        roundVideoDuration: nil, documentAttributes: nil, stickerSetID: 9, stickerAlt: nil)
    }
  }

  @Test func inventoriesAreCanonicalBoundedAndBijective() throws {
    let origin = try FederationDestination(domain: "one.example", keyID: Array(repeating: 1, count: 32))
    let a = try FederationUserReference(localID: 1_000_001, identity: Array(repeating: 2, count: 32), epoch: 1, publisher: "two.example")
    let b = try FederationUserReference(localID: 1_000_000, identity: Array(repeating: 3, count: 32), epoch: 1, publisher: "three.example")
    let inventory = try FederationReferences(origin: origin, layer: 229, users: [a, b])
    #expect(inventory.users == [b, a])
    #expect(try FederationReferences.decode(inventory.encoding) == inventory)
    #expect(try CanonicalReference.identity(a.identity, epoch: 1).identityID == a.identity)
    #expect(try CanonicalReference.identity(a.identity, epoch: 7).hosting?.epoch == 7)
    #expect(try CanonicalReference.identity(a.identity, epoch: 1) != .identity(a.identity, epoch: 2))
    #expect(try CanonicalReference.authority(a.identity).identityID == nil)
    #expect(throws: FederationError.invalidReference) { try CanonicalReference.identity(a.identity, epoch: 0) }
    // Two hostings of one identity are two accounts and may travel together.
    let later = try FederationUserReference(localID: 1_000_002, identity: a.identity, epoch: 2, publisher: "four.example")
    let hostings = try FederationReferences(origin: origin, layer: 229, users: [a, later])
    #expect(try FederationReferences.decode(hostings.encoding).users.map(\.epoch) == [1, 2])
    for users in [[], [a, a], [a, try .init(localID: b.localID, identity: a.identity, epoch: 1, publisher: b.publisher)],
      [a, try .init(localID: a.localID, identity: b.identity, epoch: 1, publisher: b.publisher)]] {
      #expect(throws: FederationError.invalidReference) {
        try FederationReferences(origin: origin, layer: 229, users: users)
      }
    }
    for id: Int64 in [0, -1, LocalIDKind.user.upperBound] {
      #expect(throws: FederationError.invalidReference) {
        try FederationUserReference(localID: id, identity: a.identity, epoch: 1, publisher: a.publisher)
      }
    }
    #expect(throws: (any Error).self) { try FederationReferences.decode(inventory.encoding + [0]) }
    for length in 0..<inventory.encoding.count {
      #expect(throws: (any Error).self) { try FederationReferences.decode(Array(inventory.encoding.prefix(length))) }
    }
  }
}
