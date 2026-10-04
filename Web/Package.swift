// swift-tools-version: 6.4
import PackageDescription

let package = Package(
  name: "BlahDiemWeb",
  dependencies: [
    .package(name: "BlahDiem", path: ".."),
    .package(url: "https://github.com/swiftwasm/JavaScriptKit.git", revision: "777848dfd70279c34f885c0c2f9e2c3fc3a45698"),
  ],
  targets: [.executableTarget(
    name: "BlahDiemWeb",
    dependencies: [
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
  )],
  swiftLanguageModes: [.v5]
)
