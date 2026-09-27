// swift-tools-version: 6.3
import PackageDescription

let package = Package(
  name: "BlahDiem",
  platforms: [.macOS(.v15), .iOS(.v18), .tvOS(.v18), .watchOS(.v11)],
  products: [
    .library(name: "BlahDiem", targets: ["BlahDiem"]),
    .executable(name: "blah-diem-device-vectors", targets: ["BlahDiemDeviceVectors"]),
  ],
  dependencies: [
    .package(url: "https://github.com/UInt8Co/diem.git", revision: "35cb123582c6b5e4bab6d5a3cfc1edd44f46d343"),
    .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),
    .package(url: "https://github.com/apple/swift-docc-plugin", exact: "1.4.6"),
  ],
  targets: [
    .target(name: "BlahDiem", dependencies: [
      .product(name: "DiemSwiftCrypto", package: "diem"),
      .product(name: "DiemSecretMemory", package: "diem"),
      .product(name: "Crypto", package: "swift-crypto"),
    ]),
    .executableTarget(name: "BlahDiemDeviceVectors", dependencies: [
      "BlahDiem", .product(name: "Crypto", package: "swift-crypto"),
    ]),
    .testTarget(name: "BlahDiemTests", dependencies: [
      "BlahDiem",
      .product(name: "DiemSwiftCrypto", package: "diem"),
      .product(name: "Crypto", package: "swift-crypto"),
    ]),
  ],
  swiftLanguageModes: [.v6]
)
