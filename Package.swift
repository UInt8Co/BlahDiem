// swift-tools-version: 6.4
import PackageDescription

let package = Package(
  name: "BlahDiem",
  platforms: [.macOS(.v15), .iOS(.v18), .tvOS(.v18), .watchOS(.v11)],
  products: [
    .library(name: "BlahDiem", targets: ["BlahDiem"]),
  ],
  dependencies: [
    .package(url: "https://github.com/UInt8Co/diem.git", revision: "9eb56cf7db0509dbd5a96cd71143e01f30b2053c"),
    .package(url: "https://github.com/apple/swift-docc-plugin", exact: "1.5.0"),
  ],
  targets: [
    .target(name: "BlahDiem", dependencies: [.product(name: "Diem", package: "diem"),
      .product(name: "DiemProfileHostingClient", package: "diem")]),
    .testTarget(
      name: "BlahDiemTests",
      dependencies: ["BlahDiem", .product(name: "DiemSwiftCrypto", package: "diem"),
        .product(name: "DiemTesting", package: "diem")]
    ),
  ],
  swiftLanguageModes: [.v6]
)
