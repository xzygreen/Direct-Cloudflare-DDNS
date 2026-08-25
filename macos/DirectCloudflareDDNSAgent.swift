import Foundation
import Security
import LocalAuthentication
import Darwin

private let keychainService = "io.github.xzygreen.direct-cloudflare-ddns"
private let keychainAccount = "cloudflare-api-token"
private let notificationKeychainAccount = "notification-secrets"
private let applicationSupportName = "DirectCloudflareDDNS"

private var shouldStop = false

private struct AgentNotificationSecrets: Codable {
    var webhookBearer = ""
    var barkKey = ""
    var gotifyToken = ""
    var telegramBotToken = ""
}

private func handleSignal(_: Int32) {
    shouldStop = true
}

private func loadToken() -> String? {
    let authenticationContext = LAContext()
    authenticationContext.interactionNotAllowed = true
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecAttrAccount as String: keychainAccount,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
        // Scheduled work must never display an authentication dialog. The App
        // provisions an ACL for this helper before registering the LaunchAgent.
        kSecUseAuthenticationContext as String: authenticationContext,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
          let data = item as? Data,
          let token = String(data: data, encoding: .utf8), !token.isEmpty else { return nil }
    return token
}

private func loadNotificationSecrets() -> AgentNotificationSecrets {
    let authenticationContext = LAContext()
    authenticationContext.interactionNotAllowed = true
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecAttrAccount as String: notificationKeychainAccount,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecUseAuthenticationContext as String: authenticationContext,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
          let data = item as? Data,
          let value = try? JSONDecoder().decode(AgentNotificationSecrets.self, from: data) else {
        return AgentNotificationSecrets()
    }
    return value
}

private func supportDirectory() -> URL {
    FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        .appendingPathComponent(applicationSupportName, isDirectory: true)
}

/// Find the owning App bundle's `Contents` directory from any path inside it.
/// The helper normally lives at `Contents/Library/LaunchServices`, while
/// `Bundle.main.resourceURL` can be reported as `Contents/Library/Resources`.
/// Counting a fixed number of parent directories therefore produces the wrong
/// result for at least one of those inputs.
private func appContentsDirectory(containing path: URL) -> URL? {
    var candidate = path.standardizedFileURL
    while candidate.path != "/" {
        if candidate.lastPathComponent == "Contents",
           candidate.deletingLastPathComponent().pathExtension == "app" {
            return candidate
        }
        candidate.deleteLastPathComponent()
    }
    return nil
}

private func runningExecutableURL() -> URL? {
    // PROC_PIDPATHINFO_MAXSIZE is a C macro that is not imported by every
    // Swift toolchain; macOS paths are bounded by PATH_MAX (1024) and this
    // larger buffer is intentionally conservative.
    var buffer = [Int8](repeating: 0, count: 4096)
    let length = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
    guard length > 0 else { return nil }
    return URL(fileURLWithPath: String(cString: buffer))
}

/// SMAppService may expose the embedded helper as `/Contents/...` in argv[0]
/// even though the process is running from the installed App bundle. Resolve
/// the resource directory from the bundle and the kernel's real executable
/// path before falling back to argv[0].
private func bundleContentsDirectory() -> URL {
    var candidates: [URL] = []

    if let executable = runningExecutableURL() {
        if let contents = appContentsDirectory(containing: executable) {
            candidates.append(contents)
        }
    }
    if let resourceURL = Bundle.main.resourceURL,
       let contents = appContentsDirectory(containing: resourceURL) {
        candidates.append(contents)
    }
    if let argument = CommandLine.arguments.first,
       let contents = appContentsDirectory(containing: URL(fileURLWithPath: argument)) {
        candidates.append(contents)
    }

    let fileManager = FileManager.default
    if let match = candidates.first(where: {
        fileManager.fileExists(
            atPath: $0.appendingPathComponent("Resources/cloudflare_ddns.py").path
        )
    }) {
        return match
    }
    return candidates.first ?? URL(fileURLWithPath: "/Contents")
}

private func pythonExecutable(resources: URL) -> URL? {
    let candidates = [
        resources.appendingPathComponent("python/bin/python3").path,
        "/usr/bin/python3",
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/Library/Frameworks/Python.framework/Versions/Current/bin/python3",
    ]
    return candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) })
        .map { URL(fileURLWithPath: $0) }
}

private func interval(from configURL: URL) -> TimeInterval {
    guard let data = try? Data(contentsOf: configURL),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let value = object["interval_seconds"] as? NSNumber else { return 300 }
    return min(86_400, max(30, value.doubleValue))
}

private func writeStatus(
    support: URL,
    exitCode: Int32,
    started: Date,
    output: String,
    error: String? = nil
) {
    var document: [String: Any] = [
        "timestamp": ISO8601DateFormatter().string(from: Date()),
        "started_at": ISO8601DateFormatter().string(from: started),
        "exit_code": Int(exitCode),
        "success": exitCode == 0,
        "output": String(output.suffix(16_384)),
    ]
    if let error { document["error"] = error }
    guard let data = try? JSONSerialization.data(
        withJSONObject: document, options: [.prettyPrinted, .sortedKeys]
    ) else { return }
    try? FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
    try? data.write(to: support.appendingPathComponent("agent-status.json"), options: .atomic)
}

private func postJSON(url: URL, document: [String: Any], bearer: String = "") {
    guard JSONSerialization.isValidJSONObject(document) else { return }
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    if !bearer.isEmpty { request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }
    request.httpBody = try? JSONSerialization.data(withJSONObject: document)
    let semaphore = DispatchSemaphore(value: 0)
    URLSession.shared.dataTask(with: request) { _, _, _ in semaphore.signal() }.resume()
    _ = semaphore.wait(timeout: .now() + 15)
}

private func sendLocalNotification(title: String, body: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    process.arguments = [
        "-e",
        "display notification (system attribute \"DDNS_BODY\") with title (system attribute \"DDNS_TITLE\")",
    ]
    var environment = ProcessInfo.processInfo.environment
    environment["DDNS_TITLE"] = title
    environment["DDNS_BODY"] = body
    process.environment = environment
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try? process.run()
}

private func deliverNotification(
    title: String,
    body: String,
    settings: [String: Any],
    secrets: AgentNotificationSecrets
) {
    if settings["local_enabled"] as? Bool ?? true {
        sendLocalNotification(title: title, body: body)
    }
    if settings["webhook_enabled"] as? Bool == true,
       let text = settings["webhook_url"] as? String, let url = URL(string: text) {
        postJSON(
            url: url,
            document: ["title": title, "message": body, "source": "Cloudflare DDNS"],
            bearer: secrets.webhookBearer
        )
    }
    if settings["bark_enabled"] as? Bool == true,
       let server = settings["bark_server"] as? String,
       let url = URL(string: server)?.appendingPathComponent("push") {
        postJSON(
            url: url,
            document: [
                "device_key": secrets.barkKey, "title": title, "body": body,
                "group": "Cloudflare DDNS",
            ]
        )
    }
    if settings["gotify_enabled"] as? Bool == true,
       let server = settings["gotify_server"] as? String,
       var components = URLComponents(string: server + "/message") {
        components.queryItems = [URLQueryItem(name: "token", value: secrets.gotifyToken)]
        if let url = components.url {
            postJSON(
                url: url,
                document: ["title": title, "message": body, "priority": 5]
            )
        }
    }
    if settings["telegram_enabled"] as? Bool == true,
       let chatID = settings["telegram_chat_id"] as? String,
       let url = URL(string: "https://api.telegram.org/bot\(secrets.telegramBotToken)/sendMessage") {
        postJSON(url: url, document: ["chat_id": chatID, "text": "\(title)\n\(body)"])
    }
}

private func processNotifications(
    configURL: URL,
    output: String,
    success: Bool,
    support: URL
) {
    guard let configData = try? Data(contentsOf: configURL),
          let config = try? JSONSerialization.jsonObject(with: configData) as? [String: Any],
          let settings = config["notifications"] as? [String: Any] else { return }

    let stateURL = support.appendingPathComponent("agent-notification-state.json")
    let previous = ((try? Data(contentsOf: stateURL))
        .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }) ?? [:]
    var ipv4 = previous["ipv4"] as? String ?? ""
    var ipv6 = previous["ipv6"] as? String ?? ""
    let oldIPv4 = ipv4
    let oldIPv6 = ipv6
    let wasFailed = previous["last_failed"] as? Bool ?? false
    for line in output.components(separatedBy: .newlines) where line.hasPrefix("@@DDNS_EVENT@@") {
        let payload = String(line.dropFirst("@@DDNS_EVENT@@".count))
        guard let data = payload.data(using: .utf8),
              let event = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              event["event"] as? String == "ip_detected",
              let family = event["family"] as? String,
              let address = event["address"] as? String else { continue }
        if family == "ipv4" { ipv4 = address }
        if family == "ipv6" { ipv6 = address }
    }

    let secrets = loadNotificationSecrets()
    if !success, !wasFailed, settings["on_failure"] as? Bool ?? true {
        deliverNotification(
            title: "Cloudflare DDNS 同步失败",
            body: "后台同步未成功，请打开应用查看运行日志。",
            settings: settings,
            secrets: secrets
        )
    } else if success {
        if wasFailed, settings["on_recovery"] as? Bool ?? true {
            deliverNotification(
                title: "Cloudflare DDNS 已恢复", body: "后台同步已恢复正常。",
                settings: settings, secrets: secrets
            )
        }
        var changes: [String] = []
        if !oldIPv4.isEmpty, oldIPv4 != ipv4 { changes.append("IPv4：\(oldIPv4) → \(ipv4)") }
        if !oldIPv6.isEmpty, oldIPv6 != ipv6 { changes.append("IPv6：\(oldIPv6) → \(ipv6)") }
        if !changes.isEmpty, settings["on_ip_change"] as? Bool ?? true {
            deliverNotification(
                title: "公网 IP 已变化", body: changes.joined(separator: "\n"),
                settings: settings, secrets: secrets
            )
        }
    }

    let next: [String: Any] = ["ipv4": ipv4, "ipv6": ipv6, "last_failed": !success]
    if let data = try? JSONSerialization.data(withJSONObject: next, options: [.sortedKeys]) {
        try? data.write(to: stateURL, options: .atomic)
    }
}

private func runSync() {
    let started = Date()
    let support = supportDirectory()
    let config = support.appendingPathComponent("config.json")
    let resources = bundleContentsDirectory().appendingPathComponent("Resources")
    let backend = resources.appendingPathComponent("cloudflare_ddns.py")
    guard FileManager.default.fileExists(atPath: config.path) else {
        writeStatus(support: support, exitCode: 2, started: started, output: "", error: "配置文件不存在")
        return
    }
    guard FileManager.default.isReadableFile(atPath: backend.path) else {
        writeStatus(
            support: support,
            exitCode: 2,
            started: started,
            output: "",
            error: "应用包内缺少 cloudflare_ddns.py：\(backend.path)"
        )
        return
    }
    guard let token = loadToken() else {
        writeStatus(support: support, exitCode: 2, started: started, output: "", error: "钥匙串中没有 API Token")
        return
    }
    guard let python = pythonExecutable(resources: resources) else {
        writeStatus(support: support, exitCode: 2, started: started, output: "", error: "找不到 Python 3.9+")
        return
    }

    let process = Process()
    process.executableURL = python
    process.arguments = [backend.path, "--config", config.path, "--json-events", "--once"]
    process.currentDirectoryURL = support
    var environment = ProcessInfo.processInfo.environment
    environment["CLOUDFLARE_API_TOKEN"] = token
    environment["PYTHONUNBUFFERED"] = "1"
    process.environment = environment
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    do {
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let output = String(decoding: data, as: UTF8.self)
        processNotifications(
            configURL: config,
            output: output,
            success: process.terminationStatus == 0,
            support: support
        )
        writeStatus(
            support: support,
            exitCode: process.terminationStatus,
            started: started,
            output: output
        )
    } catch {
        writeStatus(
            support: support, exitCode: 2, started: started, output: "",
            error: error.localizedDescription
        )
    }
}

signal(SIGTERM, handleSignal)
signal(SIGINT, handleSignal)

while !shouldStop {
    autoreleasepool { runSync() }
    let deadline = Date().addingTimeInterval(
        interval(from: supportDirectory().appendingPathComponent("config.json"))
    )
    while !shouldStop && Date() < deadline {
        Thread.sleep(forTimeInterval: min(1, deadline.timeIntervalSinceNow))
    }
}
