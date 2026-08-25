// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "DirectCloudflareDDNSCore",
    platforms: [.macOS(.v13)],
    products: [.library(name: "DDNSCore", targets: ["DDNSCore"])],
    targets: [
        .target(
            name: "DDNSCore",
            path: ".",
            exclude: [
                "DirectCloudflareDDNSApp.swift",
                "DirectCloudflareDDNSAgent.swift",
                "Info.plist",
                "io.github.xzygreen.direct-cloudflare-ddns.agent.plist",
                "Package.swift",
                "Tests",
            ],
            sources: ["CoreUtilities.swift"]
        ),
        .testTarget(
            name: "DDNSCoreTests",
            dependencies: ["DDNSCore"],
            path: "Tests/DDNSCoreTests"
        ),
    ]
)
