// swift-tools-version: 6.4
import PackageDescription

let package = Package(
  name: "BlahDiem",
  platforms: [.macOS(.v15), .iOS(.v18), .tvOS(.v18), .watchOS(.v11)],
  products: [
    .library(name: "BlahDiem", targets: ["BlahDiem"]),
  ],
  dependencies: [
    .package(url: "https://github.com/UInt8Co/diem.git", revision: "f8da6ebc131649d5a4eb220fd3bb56bc5d3ae4d5"),
    .package(url: "https://github.com/apple/swift-docc-plugin", exact: "1.5.0"),
  ],
  targets: [
    .target(name: "BlahDiem", dependencies: [.product(name: "Diem", package: "diem"),
      .product(name: "DiemProfileHostingClient", package: "diem")]),
    .testTarget(
      name: "BlahDiemTests",
      dependencies: ["BlahDiem", .product(name: "DiemSwiftCrypto", package: "diem")]
    ),
  ],
  swiftLanguageModes: [.v6]
)
