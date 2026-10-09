// swift-tools-version: 6.4
import PackageDescription

let package = Package(
  name: "BlahDiem",
  platforms: [.macOS(.v15), .iOS(.v18), .tvOS(.v18), .watchOS(.v11)],
  products: [
    .library(name: "BlahDiem", targets: ["BlahDiem"]),
  ],
  dependencies: [
    .package(url: "https://github.com/UInt8Co/diem.git", revision: "8a20cc1d1eee5cda2cf5f0f253253c3a4305d8d4"),
    .package(url: "https://github.com/apple/swift-docc-plugin", exact: "1.5.0"),
  ],
  targets: [
    .target(name: "BlahDiem", dependencies: [.product(name: "Diem", package: "diem")]),
    .testTarget(
      name: "BlahDiemTests",
      dependencies: ["BlahDiem", .product(name: "DiemSwiftCrypto", package: "diem")]
    ),
  ],
  swiftLanguageModes: [.v6]
)
