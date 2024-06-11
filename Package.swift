// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "VerifiableSwift",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "VerifiableSwift",
            targets: ["VerifiableSwift"]),
    ],
    
    dependencies: [
        .package(url: "https://github.com/METADIUM/JWTsSwift.git", .upToNextMajor(from: "0.1.2"))
    ],
    
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "VerifiableSwift",
            dependencies: [
                .product(name: "JWTsSwift", package: "JWTsSwift")
            ]),
        
        .testTarget(
            name: "VerifiableSwiftTests",
            dependencies: ["VerifiableSwift"]),
    ]
)
