// swift-tools-version: 6.3
import PackageDescription

let package = Package(
  name: "BlahDiem",
  platforms: [.macOS(.v15), .iOS(.v18), .tvOS(.v18), .watchOS(.v11)],
  products: [
    .library(name: "BlahDiem", targets: ["BlahDiem"]),
  ],
  dependencies: [
    .package(url: "https://github.com/UInt8Co/diem.git", revision: "0dfcf06d7f381881b54c741f1ffab4136bdf03dc"),
    .package(url: "https://github.com/apple/swift-docc-plugin", exact: "1.4.6"),
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
