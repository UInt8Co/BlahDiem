// swift-tools-version: 6.4
import PackageDescription

// Blah's browser runtime: Diem's web library (`DiemWeb`) plus Blah's operations, linked into
// one WASM. `DiemWeb` compiles from the pinned diem checkout, so build through `build.mjs`,
// which resolves into `.build-embedded` first. See README.md.
let package = Package(
  name: "BlahDiemWeb",
  dependencies: [
    .package(name: "BlahDiem", path: ".."),
    .package(url: "https://github.com/UInt8Co/diem.git", revision: "9eb56cf7db0509dbd5a96cd71143e01f30b2053c"),
    .package(url: "https://github.com/swiftwasm/JavaScriptKit.git", revision: "777848dfd70279c34f885c0c2f9e2c3fc3a45698"),
  ],
  targets: [
    // Diem's generic `@JS` API and browser support, from the checkout of the pin above.
    // In this package, Blah's `@JS` declarations can use its `@JS` types.
    .target(
      name: "DiemWeb",
      dependencies: [
        .product(name: "Diem", package: "diem"),
        .product(name: "DiemProfileHostingClient", package: "diem"),
        .product(name: "JavaScriptKit", package: "JavaScriptKit"),
        .product(name: "JavaScriptEventLoop", package: "JavaScriptKit"),
      ],
      path: ".build-embedded/checkouts/diem/Web/Sources/DiemWeb",
      swiftSettings: [.enableExperimentalFeature("Extern")],
      plugins: [.plugin(name: "BridgeJS", package: "JavaScriptKit")]
    ),
    .executableTarget(
      name: "BlahDiemWeb",
      dependencies: [
        "DiemWeb",
        .product(name: "BlahDiem", package: "BlahDiem"),
        .product(name: "JavaScriptKit", package: "JavaScriptKit"),
        .product(name: "JavaScriptEventLoop", package: "JavaScriptKit"),
      ],
      swiftSettings: [.enableExperimentalFeature("Extern")],
      // Embedded keeps Unicode tables optional; preserve Swift String semantics.
      linkerSettings: [
        .linkedLibrary("swiftUnicodeDataTables", .when(platforms: [.wasi])),
        .unsafeFlags(["-Xclang-linker", "-mexec-model=reactor", "-Xlinker", "--export-if-defined=__main_argc_argv"], .when(platforms: [.wasi])),
      ],
      plugins: [.plugin(name: "BridgeJS", package: "JavaScriptKit")]
    ),
  ],
  swiftLanguageModes: [.v5]
)
