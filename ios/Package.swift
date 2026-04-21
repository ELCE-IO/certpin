// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CertPinSDK",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(name: "CertPin", targets: ["CertPin"])
    ],
    targets: [
        .target(
            name: "CertPin",
            path: "Sources/CertPin"
        ),
        .testTarget(
            name: "CertPinTests",
            dependencies: ["CertPin"],
            path: "Tests/CertPinTests"
        )
    ]
)
