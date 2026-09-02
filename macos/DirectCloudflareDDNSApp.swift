import AppKit
import Foundation
import Network
import Security
import ServiceManagement
import SwiftUI
@preconcurrency import UserNotifications


private let applicationName = "Cloudflare DDNS"
private let applicationTagline = "直连检测真实公网 IP · 自动同步 Cloudflare DNS"
private let keychainService = "io.github.xzygreen.direct-cloudflare-ddns"
private let keychainAccount = "cloudflare-api-token"
private let notificationKeychainAccount = "notification-secrets"
private let maximumLogEntries = 600
private let mainWindowSceneID = "main"

private extension Notification.Name {
    static let openMainWindowRequested = Notification.Name(
        "io.github.xzygreen.direct-cloudflare-ddns.open-main-window"
    )
}


// MARK: - Application lifecycle

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldHandleReopen(
        _ sender: NSApplication,
        hasVisibleWindows _: Bool
    ) -> Bool {
        sender.activate(ignoringOtherApps: true)

        // A closed SwiftUI Window scene may no longer have an NSWindow in
        // `sender.windows`. Reuse an existing normal window when possible, and ask
        // the always-alive menu bar scene to recreate it otherwise.
        guard let mainWindow = sender.windows.first(where: {
            !($0 is NSPanel) && ($0.canBecomeMain || $0.isMiniaturized)
        }) else {
            NotificationCenter.default.post(name: .openMainWindowRequested, object: nil)
            return false
        }

        if mainWindow.isMiniaturized {
            mainWindow.deminiaturize(nil)
        }
        mainWindow.makeKeyAndOrderFront(nil)
        return false
    }
}


// MARK: - Visual language

enum Brand {
    static let sky = Color(red: 0.28, green: 0.65, blue: 1.00)
    static let blue = Color(red: 0.12, green: 0.45, blue: 0.98)
    static let indigo = Color(red: 0.35, green: 0.34, blue: 0.88)
    static let ink = Color(red: 0.05, green: 0.09, blue: 0.24)
    static let orange = Color(red: 0.98, green: 0.48, blue: 0.12)
    static let amber = Color(red: 0.98, green: 0.68, blue: 0.15)
    static let mint = Color(red: 0.15, green: 0.76, blue: 0.52)
    static let rose = Color(red: 0.96, green: 0.30, blue: 0.32)
    static let purple = Color(red: 0.58, green: 0.34, blue: 0.92)
    static let cyan = Color(red: 0.12, green: 0.65, blue: 0.94)

    // Keep the shell neutral so the accent colors communicate state instead of
    // competing with every piece of content on screen.
    static let windowBackground = Color(nsColor: .windowBackgroundColor)
    static let surface = Color(nsColor: .controlBackgroundColor)
    static let border = Color.primary.opacity(0.09)
    static let quietFill = Color.primary.opacity(0.045)
    static let pagePadding: CGFloat = 24
    static let cardRadius: CGFloat = 18

    static let hero = LinearGradient(
        colors: [
            Color(red: 0.10, green: 0.24, blue: 0.64),
            Color(red: 0.07, green: 0.14, blue: 0.42),
            Color(red: 0.04, green: 0.07, blue: 0.22)
        ],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )

    static func badge(_ color: Color) -> LinearGradient {
        LinearGradient(
            colors: [color.opacity(0.98), color.opacity(0.78)],
            startPoint: .top,
            endPoint: .bottom
        )
    }
}


// MARK: - Configuration model

struct ServiceEndpoint: Codable, Identifiable, Hashable {
    var id = UUID()
    var url: String

    init(_ url: String) {
        self.url = url
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        url = try container.decode(String.self)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(url)
    }
}


struct CloudflareSettings: Codable {
    var api_token_env = "CLOUDFLARE_API_TOKEN"
    var api_token_file: String? = nil
    var zone_name = ""
    var zone_id: String? = nil
    var bypass_proxy = false
    var create_missing_records = true

    enum CodingKeys: String, CodingKey {
        case api_token_env, api_token_file, zone_name, zone_id
        case bypass_proxy, create_missing_records
    }

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        api_token_env = try container.decodeIfPresent(String.self, forKey: .api_token_env)
            ?? "CLOUDFLARE_API_TOKEN"
        api_token_file = try container.decodeIfPresent(String.self, forKey: .api_token_file)
        zone_name = try container.decodeIfPresent(String.self, forKey: .zone_name) ?? ""
        zone_id = try container.decodeIfPresent(String.self, forKey: .zone_id)
        bypass_proxy = try container.decodeIfPresent(Bool.self, forKey: .bypass_proxy) ?? false
        create_missing_records = try container.decodeIfPresent(
            Bool.self, forKey: .create_missing_records
        ) ?? true
    }

    // zone_name is omitted rather than written as "" so the Python backend does not
    // reject an empty domain when the user identifies the zone by ID alone.
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(api_token_env, forKey: .api_token_env)
        try container.encodeIfPresent(api_token_file, forKey: .api_token_file)
        if !zone_name.isEmpty {
            try container.encode(zone_name, forKey: .zone_name)
        }
        try container.encodeIfPresent(zone_id, forKey: .zone_id)
        try container.encode(bypass_proxy, forKey: .bypass_proxy)
        try container.encode(create_missing_records, forKey: .create_missing_records)
    }
}


struct DetectionServices: Codable {
    var ipv4 = [
        ServiceEndpoint("https://api4.ipify.org"),
        ServiceEndpoint("https://ipv4.icanhazip.com"),
        ServiceEndpoint("https://v4.ident.me"),
    ]
    var ipv6 = [
        ServiceEndpoint("https://api6.ipify.org"),
        ServiceEndpoint("https://ipv6.icanhazip.com"),
        ServiceEndpoint("https://v6.ident.me"),
    ]

    enum CodingKeys: String, CodingKey { case ipv4, ipv6 }

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ipv4 = try container.decodeIfPresent([ServiceEndpoint].self, forKey: .ipv4) ?? Self().ipv4
        ipv6 = try container.decodeIfPresent([ServiceEndpoint].self, forKey: .ipv6) ?? Self().ipv6
    }
}


struct AgreementSettings: Codable {
    var ipv4 = 2
    var ipv6 = 2

    enum CodingKeys: String, CodingKey { case ipv4, ipv6 }

    init() {}

    init(from decoder: Decoder) throws {
        if let scalar = try? decoder.singleValueContainer().decode(Int.self) {
            ipv4 = scalar
            ipv6 = scalar
            return
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ipv4 = try container.decodeIfPresent(Int.self, forKey: .ipv4) ?? 2
        ipv6 = try container.decodeIfPresent(Int.self, forKey: .ipv6) ?? 2
    }
}


struct DetectionSettings: Codable {
    var bypass_proxy = true
    var allow_insecure_http = false
    var source_diagnostics = false
    var minimum_agreement = AgreementSettings()
    var services = DetectionServices()

    enum CodingKeys: String, CodingKey {
        case bypass_proxy, allow_insecure_http, source_diagnostics, minimum_agreement, services
    }

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        bypass_proxy = try container.decodeIfPresent(Bool.self, forKey: .bypass_proxy) ?? true
        allow_insecure_http = try container.decodeIfPresent(Bool.self, forKey: .allow_insecure_http) ?? false
        source_diagnostics = try container.decodeIfPresent(Bool.self, forKey: .source_diagnostics) ?? false
        minimum_agreement = try container.decodeIfPresent(
            AgreementSettings.self, forKey: .minimum_agreement
        ) ?? AgreementSettings()
        services = try container.decodeIfPresent(DetectionServices.self, forKey: .services)
            ?? DetectionServices()
    }
}


struct DNSRecord: Codable, Identifiable {
    var id = UUID()
    var name: String
    var types: [String]
    var ttl: Int
    var proxied: Bool
    var comment: String?

    enum CodingKeys: String, CodingKey {
        case name, types, ttl, proxied, comment
    }

    init(
        name: String = "home.example.com",
        types: [String] = ["A"],
        ttl: Int = 1,
        proxied: Bool = false,
        comment: String? = "Managed by direct-cloudflare-ddns"
    ) {
        self.name = name
        self.types = types
        self.ttl = ttl
        self.proxied = proxied
        self.comment = comment
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        types = try container.decodeIfPresent([String].self, forKey: .types) ?? ["A"]
        ttl = try container.decodeIfPresent(Int.self, forKey: .ttl) ?? 1
        proxied = try container.decodeIfPresent(Bool.self, forKey: .proxied) ?? false
        comment = try container.decodeIfPresent(String.self, forKey: .comment)
    }
}


struct NotificationSettings: Codable {
    var local_enabled = true
    var on_ip_change = true
    var on_failure = true
    var on_recovery = true
    var webhook_enabled = false
    var webhook_url = ""
    var bark_enabled = false
    var bark_server = "https://api.day.app"
    var gotify_enabled = false
    var gotify_server = ""
    var telegram_enabled = false
    var telegram_chat_id = ""

    enum CodingKeys: String, CodingKey {
        case local_enabled, on_ip_change, on_failure, on_recovery
        case webhook_enabled, webhook_url, bark_enabled, bark_server
        case gotify_enabled, gotify_server, telegram_enabled, telegram_chat_id
    }

    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        local_enabled = try c.decodeIfPresent(Bool.self, forKey: .local_enabled) ?? true
        on_ip_change = try c.decodeIfPresent(Bool.self, forKey: .on_ip_change) ?? true
        on_failure = try c.decodeIfPresent(Bool.self, forKey: .on_failure) ?? true
        on_recovery = try c.decodeIfPresent(Bool.self, forKey: .on_recovery) ?? true
        webhook_enabled = try c.decodeIfPresent(Bool.self, forKey: .webhook_enabled) ?? false
        webhook_url = try c.decodeIfPresent(String.self, forKey: .webhook_url) ?? ""
        bark_enabled = try c.decodeIfPresent(Bool.self, forKey: .bark_enabled) ?? false
        bark_server = try c.decodeIfPresent(String.self, forKey: .bark_server)
            ?? "https://api.day.app"
        gotify_enabled = try c.decodeIfPresent(Bool.self, forKey: .gotify_enabled) ?? false
        gotify_server = try c.decodeIfPresent(String.self, forKey: .gotify_server) ?? ""
        telegram_enabled = try c.decodeIfPresent(Bool.self, forKey: .telegram_enabled) ?? false
        telegram_chat_id = try c.decodeIfPresent(String.self, forKey: .telegram_chat_id) ?? ""
    }
}


struct NotificationSecrets: Codable, Equatable {
    var webhookBearer = ""
    var barkKey = ""
    var gotifyToken = ""
    var telegramBotToken = ""
}


struct AppConfiguration: Codable {
    var schema_version = 2
    var interval_seconds = 300
    var request_timeout_seconds = 8
    var cloudflare = CloudflareSettings()
    var ip_detection = DetectionSettings()
    var records: [DNSRecord] = []
    var notifications = NotificationSettings()

    enum CodingKeys: String, CodingKey {
        case schema_version, interval_seconds, request_timeout_seconds
        case cloudflare, ip_detection, records, notifications
    }

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schema_version = try container.decodeIfPresent(Int.self, forKey: .schema_version) ?? 1
        guard schema_version <= 2 else {
            throw AppFailure.message("配置版本 \(schema_version) 高于当前程序支持的版本 2")
        }
        interval_seconds = try container.decodeIfPresent(Int.self, forKey: .interval_seconds) ?? 300
        request_timeout_seconds = try container.decodeIfPresent(
            Int.self, forKey: .request_timeout_seconds
        ) ?? 8
        cloudflare = try container.decodeIfPresent(CloudflareSettings.self, forKey: .cloudflare)
            ?? CloudflareSettings()
        ip_detection = try container.decodeIfPresent(DetectionSettings.self, forKey: .ip_detection)
            ?? DetectionSettings()
        records = try container.decodeIfPresent([DNSRecord].self, forKey: .records) ?? []
        notifications = try container.decodeIfPresent(
            NotificationSettings.self, forKey: .notifications
        ) ?? NotificationSettings()
        schema_version = 2
    }
}


// MARK: - Keychain

enum KeychainStore {
    private static let backgroundAccessFingerprintKey =
        "backgroundAgentKeychainAccessFingerprint"
    private static let backgroundAccessAttemptFingerprintKey =
        "backgroundAgentKeychainAccessAttemptFingerprint"

    private static var backgroundAgentURL: URL {
        Bundle.main.bundleURL.appendingPathComponent(
            "Contents/Library/LaunchServices/DirectCloudflareDDNSAgent"
        )
    }

    /// The Keychain ACL contains the helper's code identity, not just its path.
    /// An App update can therefore invalidate an otherwise unchanged Token's
    /// ACL. Use the signing cdhash to refresh access exactly once per helper
    /// build instead of rewriting the item before every synchronization.
    private static func backgroundAgentFingerprint() throws -> String {
        let agentURL = backgroundAgentURL
        guard FileManager.default.isExecutableFile(atPath: agentURL.path) else {
            throw AppFailure.message("应用包内缺少后台同步助手")
        }
        var staticCode: SecStaticCode?
        var status = SecStaticCodeCreateWithPath(agentURL as CFURL, [], &staticCode)
        guard status == errSecSuccess, let staticCode else {
            throw AppFailure.message("无法读取后台助手签名：\(message(for: status))")
        }
        var signingInformation: CFDictionary?
        status = SecCodeCopySigningInformation(
            staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &signingInformation
        )
        guard status == errSecSuccess,
              let information = signingInformation as? [String: Any],
              let cdhash = information[kSecCodeInfoUnique as String] as? Data else {
            throw AppFailure.message("无法读取后台助手代码指纹：\(message(for: status))")
        }
        return cdhash.map { String(format: "%02x", $0) }.joined()
    }

    /// Make an existing Token usable by the current helper build. A failed
    /// non-interactive restore is remembered so App launches do not repeatedly
    /// ask for the login password; explicitly toggling scheduling retries it.
    static func prepareBackgroundAgentAccess(token: String, force: Bool) throws -> Bool {
        let normalizedToken = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedToken.isEmpty else { return false }
        let fingerprint = try backgroundAgentFingerprint()
        let defaults = UserDefaults.standard
        if defaults.string(forKey: backgroundAccessFingerprintKey) == fingerprint {
            return true
        }
        if !force,
           defaults.string(forKey: backgroundAccessAttemptFingerprintKey) == fingerprint {
            // 清理旧版本留下的永久失败标记，并允许本次重新尝试。
            defaults.removeObject(forKey: backgroundAccessAttemptFingerprintKey)
        }
        defaults.set(fingerprint, forKey: backgroundAccessAttemptFingerprintKey)
        do {
            try saveToken(normalizedToken)
            defaults.removeObject(forKey: backgroundAccessAttemptFingerprintKey)
            return true
        } catch {
            // 取消授权不应永久毒化该版本；下次启动或手动切换时可以重试。
            defaults.removeObject(forKey: backgroundAccessAttemptFingerprintKey)
            throw error
        }
    }

    /// Give both the foreground App and its embedded LaunchAgent access to the
    /// same keychain items. Without this explicit ACL, macOS trusts only the
    /// process which created the item and asks for the login password whenever
    /// the background helper reads it.
    private static func sharedAccess() throws -> SecAccess {
        var app: SecTrustedApplication?
        var status = SecTrustedApplicationCreateFromPath(nil, &app)
        guard status == errSecSuccess, let app else {
            throw AppFailure.message("无法授权主 App 访问钥匙串：\(message(for: status))")
        }

        let agentURL = backgroundAgentURL
        guard FileManager.default.isExecutableFile(atPath: agentURL.path) else {
            throw AppFailure.message("应用包内缺少后台同步助手")
        }
        var agent: SecTrustedApplication?
        status = agentURL.withUnsafeFileSystemRepresentation { path in
            SecTrustedApplicationCreateFromPath(path, &agent)
        }
        guard status == errSecSuccess, let agent else {
            throw AppFailure.message("无法授权后台助手访问钥匙串：\(message(for: status))")
        }

        var access: SecAccess?
        status = SecAccessCreate(
            "Cloudflare DDNS 自动同步" as CFString,
            [app, agent] as CFArray,
            &access
        )
        guard status == errSecSuccess, let access else {
            throw AppFailure.message("无法创建钥匙串共享权限：\(message(for: status))")
        }
        return access
    }

    static func loadToken() -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
              let data = item as? Data,
              let token = String(data: data, encoding: .utf8) else {
            return ""
        }
        return token
    }

    static func saveToken(_ token: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
        guard !token.isEmpty else {
            // 清空 Token 是唯一需要删除的场景。
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw AppFailure.message("无法从钥匙串移除 Token：\(message(for: status))")
            }
            return
        }

        // 就地更新已有条目；失败时旧 Token 仍保留，不会出现“删了旧的、新的没存上”。
        let attributes: [String: Any] = [
            kSecValueData as String: Data(token.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            kSecAttrAccess as String: try sharedAccess(),
        ]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item.merge(attributes) { _, new in new }
            status = SecItemAdd(item as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw AppFailure.message("无法保存 Token 到钥匙串：\(message(for: status))")
        }
        // The write above installed an ACL for this exact helper identity.
        let fingerprint = try backgroundAgentFingerprint()
        UserDefaults.standard.set(fingerprint, forKey: backgroundAccessFingerprintKey)
        UserDefaults.standard.removeObject(forKey: backgroundAccessAttemptFingerprintKey)
    }

    static func loadNotificationSecrets() -> NotificationSecrets {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: notificationKeychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let secrets = try? JSONDecoder().decode(NotificationSecrets.self, from: data) else {
            return NotificationSecrets()
        }
        return secrets
    }

    static func saveNotificationSecrets(_ secrets: NotificationSecrets) throws {
        let data = try JSONEncoder().encode(secrets)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: notificationKeychainAccount,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            kSecAttrAccess as String: try sharedAccess(),
        ]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item.merge(attributes) { _, new in new }
            status = SecItemAdd(item as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw AppFailure.message("无法保存通知凭据到钥匙串：\(message(for: status))")
        }
    }

    private static func message(for status: OSStatus) -> String {
        SecCopyErrorMessageString(status, nil) as String? ?? "错误码 \(status)"
    }
}


// MARK: - Log

enum LogLevel: String, CaseIterable {
    case app, info, warning, error, debug

    var color: Color {
        switch self {
        case .app: return Brand.blue
        case .info: return Brand.cyan
        case .warning: return Brand.amber
        case .error: return Brand.rose
        case .debug: return Brand.purple
        }
    }

    var symbol: String {
        switch self {
        case .app: return "app.badge.checkmark"
        case .info: return "info.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .error: return "xmark.octagon.fill"
        case .debug: return "ladybug.fill"
        }
    }
}


enum LogFilter: String, CaseIterable, Identifiable {
    case all, app, info, warning, error, debug

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: return "全部"
        case .app: return "应用"
        case .info: return "信息"
        case .warning: return "警告"
        case .error: return "错误"
        case .debug: return "调试"
        }
    }

    var level: LogLevel? {
        self == .all ? nil : LogLevel(rawValue: rawValue)
    }
}


struct LogEntry: Identifiable {
    let id = UUID()
    let date: Date
    let level: LogLevel
    let text: String

    static let timeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter
    }()

    var timestamp: String {
        LogEntry.timeFormatter.string(from: date)
    }
}


struct BackendEvent: Decodable {
    let event: String
    var family: String?
    var address: String?
    var action: String?
    var record_type: String?
    var name: String?
    var message: String?
    var dry_run: Bool?
}


struct SyncHistoryEntry: Codable, Identifiable {
    var id = UUID()
    let date: Date
    let action: String
    let success: Bool
    let duration: TimeInterval
    let ipv4: String
    let ipv6: String
    let changes: [String]
    let summary: String
}


struct RuntimeState: Codable {
    var lastSync: Date?
    var detectedIPv4 = ""
    var detectedIPv6 = ""
    var lastRunFailed = false
    var history: [SyncHistoryEntry] = []
}


struct DiscoveredZone: Decodable, Identifiable, Hashable {
    let id: String
    let name: String
    let status: String?
}


struct DiscoveredRecord: Decodable, Identifiable {
    let id: String
    let name: String
    let type: String
    let content: String?
    let ttl: Int?
    let proxied: Bool?
    let comment: String?
}


struct DiscoveryDocument: Decodable {
    let zones: [DiscoveredZone]
    let records: [DiscoveredRecord]
}


struct AgentStatus: Decodable {
    let timestamp: String
    let started_at: String?
    let exit_code: Int
    let success: Bool
    let skipped: Bool?
    let output: String
    let events: [String]?
    let error: String?
}


struct UpdateManifest: Decodable {
    let version: String
    let url: String
    let sha256: String
    let notes: String?
}


enum RunState {
    case idle
    case running
    case success
    case failure

    var tint: Color {
        switch self {
        case .idle: return .secondary
        case .running: return Brand.blue
        case .success: return Brand.mint
        case .failure: return Brand.rose
        }
    }

    var symbol: String {
        switch self {
        case .idle: return "moon.zzz.fill"
        case .running: return "arrow.triangle.2.circlepath"
        case .success: return "checkmark.circle.fill"
        case .failure: return "exclamationmark.triangle.fill"
        }
    }
}


// MARK: - View model

@MainActor
final class AppModel: ObservableObject {
    @Published var config = AppConfiguration()
    @Published var token = ""
    @Published var notificationSecrets = NotificationSecrets()
    @Published var logEntries: [LogEntry] = []
    @Published var statusText = "就绪"
    @Published var runState: RunState = .idle
    @Published var currentAction = ""

    // Keep a snapshot of the values loaded from Keychain. Routine operations
    // persist the JSON configuration only; even an explicit Save must not
    // rewrite Keychain ACLs when no credential actually changed.
    private var persistedToken = ""
    private var persistedNotificationSecrets = NotificationSecrets()
    @Published var schedulerEnabled = false
    @Published var launchAtLoginEnabled = false
    @Published var usingBackgroundAgent = false
    @Published var nextSync: Date?
    @Published var lastSync: Date?
    @Published var detectedIPv4 = ""
    @Published var detectedIPv6 = ""
    @Published var configurationLoadError: String?
    @Published var history: [SyncHistoryEntry] = []
    @Published var discoveredZones: [DiscoveredZone] = []
    @Published var discoveredRecords: [DiscoveredRecord] = []
    @Published var showOnboarding = false
    @Published var updateStatus = "尚未检查更新"
    @Published private var currentTime = Date()

    private var runningProcess: Process?
    private var tickTimer: Timer?
    private var activity: NSObjectProtocol?
    private var currentRunStarted: Date?
    private var currentRunChanges: [String] = []
    private var addressesBeforeRun: (v4: String, v6: String) = ("", "")
    private var lastRunFailed = false
    private let pathMonitor = NWPathMonitor()
    private var hasObservedNetworkPath = false
    private var networkWasAvailable = true
    private var wakeObserver: NSObjectProtocol?
    private var lastAgentStatusTimestamp = ""
    private var agentPollTick = 0

    var isRunning: Bool { runState == .running }

    private var supportDirectory: URL {
        let base = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        return base.appendingPathComponent("DirectCloudflareDDNS", isDirectory: true)
    }

    var configURL: URL {
        supportDirectory.appendingPathComponent("config.json")
    }

    private var backupDirectory: URL {
        supportDirectory.appendingPathComponent("Backups", isDirectory: true)
    }

    private var runtimeStateURL: URL {
        supportDirectory.appendingPathComponent("runtime-state.json")
    }

    private var syncRequestURL: URL {
        supportDirectory.appendingPathComponent("sync-now.request")
    }

    var hasToken: Bool {
        !token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var ipv4AgreementUpperBound: Int {
        max(1, config.ip_detection.services.ipv4.count)
    }

    var ipv6AgreementUpperBound: Int {
        max(1, config.ip_detection.services.ipv6.count)
    }

    var remainingSeconds: Int? {
        guard schedulerEnabled, let date = nextSync else { return nil }
        return max(0, Int(date.timeIntervalSince(currentTime).rounded()))
    }

    var schedulerDescription: String {
        guard let remaining = remainingSeconds else { return "定时同步未启动" }
        return String(format: "%02d:%02d 后同步", remaining / 60, remaining % 60)
    }

    var intervalDescription: String {
        let seconds = config.interval_seconds
        if seconds % 3600 == 0 { return "每 \(seconds / 3600) 小时" }
        if seconds % 60 == 0 { return "每 \(seconds / 60) 分钟" }
        return "每 \(seconds) 秒"
    }

    var lastSyncDescription: String {
        guard let lastSync else { return "尚未同步" }
        let formatter = DateFormatter()
        formatter.dateFormat = "MM-dd HH:mm:ss"
        return formatter.string(from: lastSync)
    }

    init() {
        token = KeychainStore.loadToken()
        notificationSecrets = KeychainStore.loadNotificationSecrets()
        persistedToken = token
        persistedNotificationSecrets = notificationSecrets
        loadConfiguration()
        loadRuntimeState()
        lastAgentStatusTimestamp = UserDefaults.standard.string(
            forKey: "lastAgentStatusTimestamp"
        ) ?? ""
        if config.records.isEmpty {
            config.records = [DNSRecord(name: "home.example.com")]
        }
        showOnboarding = !hasToken
            || (config.cloudflare.zone_name.isEmpty && config.cloudflare.zone_id == nil)
        schedulerEnabled = UserDefaults.standard.bool(forKey: "schedulerEnabled")
        if #available(macOS 13.0, *) {
            launchAtLoginEnabled = SMAppService.mainApp.status == .enabled
            usingBackgroundAgent = SMAppService.agent(
                plistName: "io.github.xzygreen.direct-cloudflare-ddns.agent.plist"
            ).status == .enabled
        }
        if schedulerEnabled {
            DispatchQueue.main.async { [weak self] in
                self?.startScheduler(runImmediately: false)
            }
        }
        startConnectivityMonitoring()
        checkForUpdatesIfDue()
    }

    deinit {
        tickTimer?.invalidate()
        runningProcess?.terminate()
        if let activity {
            ProcessInfo.processInfo.endActivity(activity)
        }
        pathMonitor.cancel()
        if let wakeObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(wakeObserver)
        }
    }

    // MARK: Logging

    func appendLog(_ text: String, level: LogLevel = .app) {
        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }
            logEntries.append(LogEntry(date: Date(), level: level, text: line))
        }
        if logEntries.count > maximumLogEntries {
            logEntries.removeFirst(logEntries.count - maximumLogEntries)
        }
    }

    private func ingestBackendLine(_ line: String) {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        if trimmed.hasPrefix("@@DDNS_EVENT@@") {
            let payload = String(trimmed.dropFirst("@@DDNS_EVENT@@".count))
            if let data = payload.data(using: .utf8),
               let event = try? JSONDecoder().decode(BackendEvent.self, from: data) {
                handleBackendEvent(event)
            }
            return
        }
        // 当前地址只信任结构化 ip_detected 事件；错误日志中的私网地址不能污染概览。
        appendLog(trimmed, level: Self.level(of: trimmed))
    }

    private func handleBackendEvent(_ event: BackendEvent) {
        switch event.event {
        case "ip_detected":
            if event.family == "ipv4", let address = event.address { detectedIPv4 = address }
            if event.family == "ipv6", let address = event.address { detectedIPv6 = address }
        case "record_change":
            let verb = event.action == "create" ? "创建" : "更新"
            let preview = event.dry_run == true ? "演练" : verb
            currentRunChanges.append(
                "\(preview) \(event.record_type ?? "DNS") \(event.name ?? "") → \(event.address ?? "")"
            )
        case "ip_detection_failed":
            if let message = event.message { currentRunChanges.append("检测失败：\(message)") }
        default:
            break
        }
    }

    private func loadRuntimeState() {
        guard let data = try? Data(contentsOf: runtimeStateURL),
              let state = try? JSONDecoder().decode(RuntimeState.self, from: data) else { return }
        lastSync = state.lastSync
        detectedIPv4 = state.detectedIPv4
        detectedIPv6 = state.detectedIPv6
        lastRunFailed = state.lastRunFailed
        history = Array(state.history.prefix(100))
    }

    private func persistRuntimeState() {
        let state = RuntimeState(
            lastSync: lastSync,
            detectedIPv4: detectedIPv4,
            detectedIPv6: detectedIPv6,
            lastRunFailed: lastRunFailed,
            history: Array(history.prefix(100))
        )
        do {
            try FileManager.default.createDirectory(
                at: supportDirectory, withIntermediateDirectories: true
            )
            let data = try JSONEncoder().encode(state)
            try data.write(to: runtimeStateURL, options: .atomic)
        } catch {
            appendLog("保存运行状态失败：\(error.localizedDescription)", level: .warning)
        }
    }

    private static func level(of line: String) -> LogLevel {
        if line.contains(" ERROR ") || line.contains("Traceback") { return .error }
        if line.contains(" WARNING ") { return .warning }
        if line.contains(" DEBUG ") { return .debug }
        return .info
    }

    func clearLog() {
        logEntries.removeAll()
    }

    func clearHistory() {
        history.removeAll()
        persistRuntimeState()
        appendLog("同步历史已清空")
    }

    func copyLog() {
        let text = logEntries.map { "[\($0.timestamp)] \($0.text)" }.joined(separator: "\n")
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        appendLog("运行日志已复制到剪贴板")
    }

    func revealConfiguration() {
        NSWorkspace.shared.activateFileViewerSelecting([configURL])
    }

    // MARK: Configuration

    private func loadConfiguration() {
        guard FileManager.default.fileExists(atPath: configURL.path) else { return }
        do {
            let data = try Data(contentsOf: configURL)
            let rawObject = try? JSONSerialization.jsonObject(with: data)
            let sourceVersion = (rawObject as? [String: Any])?["schema_version"] as? Int ?? 1
            config = try JSONDecoder().decode(AppConfiguration.self, from: data)
            configurationLoadError = nil
            appendLog("已载入配置：\(configURL.path)")
            if sourceVersion < config.schema_version {
                appendLog(
                    "配置已从架构版本 \(sourceVersion) 迁移到 \(config.schema_version)；下次保存时写入新格式",
                    level: .warning
                )
            }
        } catch {
            configurationLoadError = error.localizedDescription
            appendLog(
                "读取配置失败；为保护原文件，保存与同步已锁定：\(error.localizedDescription)",
                level: .error
            )
        }
    }

    private func validateConfiguration(requiresToken: Bool) throws {
        if let configurationLoadError,
           FileManager.default.fileExists(atPath: configURL.path) {
            throw AppFailure.message(
                "原配置加载失败，已禁止覆盖。请先恢复备份或修复配置文件：\(configurationLoadError)"
            )
        }
        let rawZoneName = config.cloudflare.zone_name
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if rawZoneName.isEmpty {
            config.cloudflare.zone_name = ""
        } else {
            config.cloudflare.zone_name = try DomainValidator.normalized(
                rawZoneName, allowWildcard: false
            )
        }
        if let zoneID = config.cloudflare.zone_id {
            let trimmed = zoneID.trimmingCharacters(in: .whitespacesAndNewlines)
            config.cloudflare.zone_id = trimmed.isEmpty ? nil : trimmed
        }
        guard !config.cloudflare.zone_name.isEmpty || config.cloudflare.zone_id != nil else {
            throw AppFailure.message("请填写 Cloudflare 区域名或 Zone ID")
        }
        guard (30...86400).contains(config.interval_seconds) else {
            throw AppFailure.message("同步间隔必须在 30 到 86400 秒之间")
        }
        guard (1...60).contains(config.request_timeout_seconds) else {
            throw AppFailure.message("请求超时必须在 1 到 60 秒之间")
        }

        try validateServices(config.ip_detection.services.ipv4, label: "IPv4")
        try validateServices(config.ip_detection.services.ipv6, label: "IPv6")

        guard !config.records.isEmpty else {
            throw AppFailure.message("请至少添加一条 DNS 记录")
        }

        let zone = config.cloudflare.zone_name
        var seen = Set<String>()
        for index in config.records.indices {
            config.records[index].name = try DomainValidator.normalized(
                config.records[index].name, allowWildcard: true
            )
            config.records[index].types = Array(Set(config.records[index].types)).sorted()
            let record = config.records[index]
            let position = index + 1
            guard !record.name.isEmpty else {
                throw AppFailure.message("第 \(position) 条记录的域名为空")
            }
            guard !record.types.isEmpty else {
                throw AppFailure.message("第 \(position) 条记录至少选择 A 或 AAAA")
            }
            guard record.ttl == 1 || (60...86400).contains(record.ttl) else {
                throw AppFailure.message("第 \(position) 条记录的 TTL 必须为 1 或 60-86400")
            }
            guard !record.proxied || record.ttl == 1 else {
                throw AppFailure.message("第 \(position) 条代理记录必须使用自动 TTL（1）")
            }
            if !zone.isEmpty, record.name != zone, !record.name.hasSuffix("." + zone) {
                throw AppFailure.message("第 \(position) 条记录 \(record.name) 不属于区域 \(zone)")
            }
            for type in record.types where !seen.insert("\(type) \(record.name)").inserted {
                throw AppFailure.message("第 \(position) 条记录与前面重复：\(type) \(record.name)")
            }
        }

        let types = Set(config.records.flatMap(\.types))
        if types.contains("A"),
           !(1...ipv4AgreementUpperBound).contains(config.ip_detection.minimum_agreement.ipv4) {
            throw AppFailure.message(
                "IPv4 共识票数必须在 1 到 \(ipv4AgreementUpperBound) 之间"
            )
        }
        if types.contains("AAAA"),
           !(1...ipv6AgreementUpperBound).contains(config.ip_detection.minimum_agreement.ipv6) {
            throw AppFailure.message(
                "IPv6 共识票数必须在 1 到 \(ipv6AgreementUpperBound) 之间"
            )
        }

        let notifications = config.notifications
        if notifications.webhook_enabled {
            try validateNotificationURL(notifications.webhook_url, label: "Webhook")
        }
        if notifications.bark_enabled {
            try validateNotificationURL(notifications.bark_server, label: "Bark 服务器")
            guard !notificationSecrets.barkKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw AppFailure.message("启用 Bark 前请填写设备 Key")
            }
        }
        if notifications.gotify_enabled {
            try validateNotificationURL(notifications.gotify_server, label: "Gotify 服务器")
            guard !notificationSecrets.gotifyToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw AppFailure.message("启用 Gotify 前请填写应用 Token")
            }
        }
        if notifications.telegram_enabled {
            guard !notifications.telegram_chat_id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  !notificationSecrets.telegramBotToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw AppFailure.message("启用 Telegram 前请填写 Bot Token 和 Chat ID")
            }
        }

        if requiresToken && !hasToken {
            throw AppFailure.message("请填写 Cloudflare API Token")
        }
    }

    private func validateNotificationURL(_ value: String, label: String) throws {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: text),
              ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
              url.host != nil else {
            throw AppFailure.message("\(label)地址无效")
        }
    }

    private func validateServices(_ services: [ServiceEndpoint], label: String) throws {
        guard !services.isEmpty else {
            throw AppFailure.message("\(label) 查询服务列表不能为空")
        }
        guard services.count <= 10 else {
            throw AppFailure.message("\(label) 查询服务最多允许 10 个")
        }
        var seen = Set<String>()
        for service in services {
            let url = service.url.trimmingCharacters(in: .whitespacesAndNewlines)
            guard url.hasPrefix("http://") || url.hasPrefix("https://"),
                  let parsed = URL(string: url), parsed.host != nil else {
                throw AppFailure.message("\(label) 查询服务地址无效：\(service.url)")
            }
            guard parsed.user == nil, parsed.password == nil else {
                throw AppFailure.message("\(label) 查询服务地址不能包含账号密码：\(service.url)")
            }
            guard parsed.fragment == nil else {
                throw AppFailure.message("\(label) 查询服务地址不能包含 URL 片段：\(service.url)")
            }
            guard seen.insert(url.lowercased()).inserted else {
                throw AppFailure.message("\(label) 查询服务重复：\(url)")
            }
            if parsed.scheme?.lowercased() == "http",
               !config.ip_detection.allow_insecure_http {
                throw AppFailure.message(
                    "\(label) 来源使用 HTTP：请改用 HTTPS，或显式开启“允许不安全的 HTTP 查询来源”"
                )
            }
        }
    }

    func saveConfiguration(
        report: Bool = true,
        persistCredentials: Bool = true
    ) throws {
        try validateConfiguration(requiresToken: false)
        config.schema_version = 2
        config.cloudflare.api_token_env = "CLOUDFLARE_API_TOKEN"
        config.cloudflare.api_token_file = nil
        for index in config.ip_detection.services.ipv4.indices {
            config.ip_detection.services.ipv4[index].url = config.ip_detection.services.ipv4[index]
                .url.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        for index in config.ip_detection.services.ipv6.indices {
            config.ip_detection.services.ipv6[index].url = config.ip_detection.services.ipv6[index]
                .url.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        try FileManager.default.createDirectory(
            at: supportDirectory,
            withIntermediateDirectories: true
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(config)
        try createConfigurationBackupIfNeeded(replacingWith: data)
        try data.write(to: configURL, options: .atomic)
        if persistCredentials {
            try persistCredentialChanges()
        }
        if report {
            appendLog("配置已保存；凭据已由 macOS 钥匙串安全保管")
            statusText = "配置已保存"
        }
    }

    @discardableResult
    private func persistCredentialChanges() throws -> Bool {
        let normalizedToken = token.trimmingCharacters(in: .whitespacesAndNewlines)
        var changed = false
        if normalizedToken != persistedToken {
            try KeychainStore.saveToken(normalizedToken)
            persistedToken = normalizedToken
            changed = true
        }
        if notificationSecrets != persistedNotificationSecrets {
            try KeychainStore.saveNotificationSecrets(notificationSecrets)
            persistedNotificationSecrets = notificationSecrets
            changed = true
        }
        return changed
    }

    private func createConfigurationBackupIfNeeded(replacingWith newData: Data) throws {
        guard FileManager.default.fileExists(atPath: configURL.path) else { return }
        if let existing = try? Data(contentsOf: configURL), existing == newData { return }
        try FileManager.default.createDirectory(
            at: backupDirectory,
            withIntermediateDirectories: true
        )
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss-SSS"
        let backup = backupDirectory.appendingPathComponent(
            "config-\(formatter.string(from: Date())).json"
        )
        try FileManager.default.copyItem(at: configURL, to: backup)
        let backups = try FileManager.default.contentsOfDirectory(
            at: backupDirectory,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ).filter { $0.pathExtension == "json" }
            .sorted {
                let left = (try? $0.resourceValues(forKeys: [.contentModificationDateKey]))?
                    .contentModificationDate ?? .distantPast
                let right = (try? $1.resourceValues(forKeys: [.contentModificationDateKey]))?
                    .contentModificationDate ?? .distantPast
                return left > right
            }
        for stale in backups.dropFirst(5) {
            try? FileManager.default.removeItem(at: stale)
        }
    }

    func restoreLatestConfigurationBackup() {
        do {
            let backups = try FileManager.default.contentsOfDirectory(
                at: backupDirectory,
                includingPropertiesForKeys: [.contentModificationDateKey],
                options: [.skipsHiddenFiles]
            ).filter { $0.pathExtension == "json" }
                .sorted {
                    let left = (try? $0.resourceValues(forKeys: [.contentModificationDateKey]))?
                        .contentModificationDate ?? .distantPast
                    let right = (try? $1.resourceValues(forKeys: [.contentModificationDateKey]))?
                        .contentModificationDate ?? .distantPast
                    return left > right
                }
            guard let latest = backups.first else {
                throw AppFailure.message("没有可恢复的配置备份")
            }
            let data = try Data(contentsOf: latest)
            let restored = try JSONDecoder().decode(AppConfiguration.self, from: data)
            try data.write(to: configURL, options: .atomic)
            config = restored
            configurationLoadError = nil
            appendLog("已恢复配置备份：\(latest.lastPathComponent)")
            statusText = "配置已恢复"
        } catch {
            appendLog("恢复配置失败：\(error.localizedDescription)", level: .error)
            statusText = "恢复失败"
            runState = .failure
        }
    }

    func saveButtonPressed() {
        do {
            try saveConfiguration()
            if schedulerEnabled {
                startScheduler(runImmediately: false)
            }
        } catch {
            statusText = "保存失败"
            runState = .failure
            appendLog(error.localizedDescription, level: .error)
        }
    }

    // MARK: Backend

    private static var pythonVersionCache: [String: Bool] = [:]

    /// 只可执行还不够：后端要求 Python 3.9+，启动前先探测一次版本（结果缓存）。
    private static func meetsMinimumPythonVersion(_ path: String) -> Bool {
        if let cached = pythonVersionCache[path] { return cached }
        let probe = Process()
        probe.executableURL = URL(fileURLWithPath: path)
        probe.arguments = ["-c", "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"]
        probe.standardOutput = FileHandle.nullDevice
        probe.standardError = FileHandle.nullDevice
        var satisfied = false
        do {
            try probe.run()
            probe.waitUntilExit()
            satisfied = probe.terminationStatus == 0
        } catch {
            satisfied = false
        }
        pythonVersionCache[path] = satisfied
        return satisfied
    }

    private func pythonExecutable() -> (url: URL?, outdated: [String]) {
        var candidates: [String] = []
        if let embedded = Bundle.main.resourceURL?
            .appendingPathComponent("python/bin/python3").path {
            candidates.append(embedded)
        }
        candidates += [
            "/usr/bin/python3",
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/Library/Frameworks/Python.framework/Versions/Current/bin/python3",
        ]
        var outdated: [String] = []
        for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
            if Self.meetsMinimumPythonVersion(path) {
                return (URL(fileURLWithPath: path), [])
            }
            outdated.append(path)
        }
        return (nil, outdated)
    }

    private func backendURL() -> URL? {
        Bundle.main.url(forResource: "cloudflare_ddns", withExtension: "py")
    }

    func checkIP() {
        runBackend(arguments: ["--check-ip"], requiresToken: false, action: "检测公网 IP")
    }

    func testConnection() {
        runBackend(arguments: ["--test-connection"], requiresToken: true, action: "连接测试")
    }

    func discoverCloudflare(zoneID: String? = nil) {
        guard !isRunning else { return }
        guard hasToken else {
            appendLog("请先填写 Cloudflare API Token", level: .error)
            return
        }
        do {
            try persistCredentialChanges()
        } catch {
            appendLog("无法保存 Cloudflare API Token：\(error.localizedDescription)", level: .error)
            return
        }
        let lookup = pythonExecutable()
        guard let python = lookup.url, let backend = backendURL() else {
            appendLog("发现区域需要 Python 3.9+ 和完整的应用后端", level: .error)
            return
        }
        let process = Process()
        process.executableURL = python
        process.arguments = [backend.path, "--discover", "--api-token-stdin"]
            + (zoneID.map { ["--discover-zone-id", $0] } ?? [])
        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: "CLOUDFLARE_API_TOKEN")
        environment["PYTHONUNBUFFERED"] = "1"
        process.environment = environment
        let tokenInput = Pipe()
        process.standardInput = tokenInput
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        do {
            try process.run()
            tokenInput.fileHandleForWriting.write(
                Data((token.trimmingCharacters(in: .whitespacesAndNewlines) + "\n").utf8)
            )
            try? tokenInput.fileHandleForWriting.close()
        } catch {
            try? tokenInput.fileHandleForWriting.close()
            appendLog("无法启动 Cloudflare 发现任务：\(error.localizedDescription)", level: .error)
            return
        }
        runningProcess = process
        runState = .running
        currentAction = "发现 Cloudflare 配置"
        statusText = zoneID == nil ? "正在读取区域…" : "正在读取 DNS 记录…"
        appendLog(statusText)

        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let model = self else { return }
            let output = stdout.fileHandleForReading.readDataToEndOfFile()
            let errors = stderr.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            DispatchQueue.main.async {
                model.runningProcess = nil
                model.currentAction = ""
                let errorText = String(decoding: errors, as: UTF8.self)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                guard process.terminationStatus == 0 else {
                    model.runState = .failure
                    model.statusText = "读取 Cloudflare 配置失败"
                    model.appendLog(
                        errorText.isEmpty ? "Cloudflare 发现任务失败" : errorText,
                        level: .error
                    )
                    return
                }
                do {
                    let document = try JSONDecoder().decode(DiscoveryDocument.self, from: output)
                    model.discoveredZones = document.zones
                    model.discoveredRecords = document.records.sorted {
                        ($0.name, $0.type) < ($1.name, $1.type)
                    }
                    model.runState = .success
                    model.statusText = zoneID == nil ? "已读取区域" : "已读取 DNS 记录"
                    model.appendLog(
                        zoneID == nil
                            ? "发现 \(document.zones.count) 个可访问区域"
                            : "发现 \(document.records.count) 条 A/AAAA 记录"
                    )
                } catch {
                    model.runState = .failure
                    model.statusText = "响应解析失败"
                    model.appendLog("解析 Cloudflare 响应失败：\(error.localizedDescription)", level: .error)
                }
            }
        }
    }

    func selectDiscoveredZone(_ zone: DiscoveredZone) {
        config.cloudflare.zone_id = zone.id
        config.cloudflare.zone_name = zone.name
        if config.records.count == 1, config.records[0].name == "home.example.com" {
            config.records.removeAll()
        }
        discoveredRecords = []
        discoverCloudflare(zoneID: zone.id)
    }

    func isRecordImported(_ record: DiscoveredRecord) -> Bool {
        config.records.contains { $0.name == record.name && $0.types.contains(record.type) }
    }

    func importDiscoveredRecord(_ record: DiscoveredRecord) {
        guard !isRecordImported(record) else { return }
        config.records.append(
            DNSRecord(
                name: record.name,
                types: [record.type],
                ttl: record.ttl ?? 1,
                proxied: record.proxied ?? false,
                comment: record.comment
            )
        )
        appendLog("已添加 \(record.type) \(record.name) 到配置，保存后生效")
    }

    func finishOnboarding() {
        do {
            try saveConfiguration()
            showOnboarding = false
            testConnection()
        } catch {
            appendLog("无法完成设置：\(error.localizedDescription)", level: .error)
            statusText = "设置未完成"
            runState = .failure
        }
    }

    func dryRun() {
        runBackend(arguments: ["--once", "--dry-run"], requiresToken: true, action: "演练")
    }

    func syncNow() {
        runBackend(arguments: ["--once"], requiresToken: true, action: "同步")
    }

    func cancelRun() {
        guard let process = runningProcess, process.isRunning else { return }
        appendLog("正在停止当前任务…", level: .warning)
        process.terminate()
    }

    private func runBackend(
        arguments: [String],
        requiresToken: Bool,
        action: String
    ) {
        guard !isRunning else {
            appendLog("已有任务正在运行，本次\(action)已跳过", level: .warning)
            return
        }
        do {
            try validateConfiguration(requiresToken: requiresToken)
            if requiresToken {
                try persistCredentialChanges()
            }
            try saveConfiguration(report: false, persistCredentials: false)
        } catch {
            statusText = "配置有误"
            runState = .failure
            appendLog(error.localizedDescription, level: .error)
            return
        }
        let lookup = pythonExecutable()
        guard let python = lookup.url else {
            statusText = "缺少 Python"
            runState = .failure
            if lookup.outdated.isEmpty {
                appendLog("未找到 Python 3；请安装 Python 3.9 或更高版本", level: .error)
            } else {
                appendLog(
                    "已安装的 Python 版本低于 3.9（\(lookup.outdated.joined(separator: "、"))）；请升级后重试",
                    level: .error
                )
            }
            return
        }
        guard let backend = backendURL() else {
            statusText = "应用文件不完整"
            runState = .failure
            appendLog("应用包内缺少 cloudflare_ddns.py", level: .error)
            return
        }

        let process = Process()
        process.executableURL = python
        process.arguments = [backend.path, "--config", configURL.path, "--json-events"]
            + (requiresToken ? ["--api-token-stdin"] : [])
            + arguments
        process.currentDirectoryURL = supportDirectory
        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: "CLOUDFLARE_API_TOKEN")
        environment["PYTHONUNBUFFERED"] = "1"
        process.environment = environment
        let tokenInput: Pipe? = requiresToken ? Pipe() : nil
        process.standardInput = tokenInput
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            if let tokenInput {
                tokenInput.fileHandleForWriting.write(
                    Data((token.trimmingCharacters(in: .whitespacesAndNewlines) + "\n").utf8)
                )
                try? tokenInput.fileHandleForWriting.close()
            }
        } catch {
            try? tokenInput?.fileHandleForWriting.close()
            statusText = "启动失败"
            runState = .failure
            appendLog("无法启动后台程序：\(error.localizedDescription)", level: .error)
            return
        }

        runningProcess = process
        currentRunStarted = Date()
        currentRunChanges = []
        addressesBeforeRun = (detectedIPv4, detectedIPv6)
        runState = .running
        currentAction = action
        statusText = "正在\(action)…"
        appendLog("开始\(action)")

        // Stream output line by line so long syncs report progress live.
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let model = self else { return }
            let handle = pipe.fileHandleForReading
            var buffer = Data()
            while true {
                let chunk = handle.availableData
                if chunk.isEmpty { break }
                buffer.append(chunk)
                while let index = buffer.firstIndex(of: 0x0A) {
                    let lineData = buffer[buffer.startIndex..<index]
                    buffer.removeSubrange(buffer.startIndex...index)
                    let line = String(decoding: lineData, as: UTF8.self)
                    DispatchQueue.main.async { model.ingestBackendLine(line) }
                }
            }
            if !buffer.isEmpty {
                let line = String(decoding: buffer, as: UTF8.self)
                DispatchQueue.main.async { model.ingestBackendLine(line) }
            }
            process.waitUntilExit()
            let code = process.terminationStatus
            let reason = process.terminationReason
            DispatchQueue.main.async {
                model.finishRun(action: action, code: code, reason: reason)
            }
        }
    }

    private func finishRun(
        action: String,
        code: Int32,
        reason: Process.TerminationReason
    ) {
        runningProcess = nil
        currentAction = ""
        let duration = Date().timeIntervalSince(currentRunStarted ?? Date())
        currentRunStarted = nil
        if reason == .uncaughtSignal {
            runState = .failure
            statusText = "\(action)已取消"
            appendLog("\(action)已取消", level: .warning)
            addHistory(action: action, success: false, duration: duration, summary: "用户取消")
            return
        }
        if code == 3 {
            runState = .idle
            statusText = "已有同步正在运行"
            appendLog("另一同步实例正在运行，本次\(action)已跳过", level: .warning)
            addHistory(action: action, success: true, duration: duration, summary: "已跳过：实例忙")
        } else if code == 0 {
            runState = .success
            statusText = "\(action)成功"
            appendLog("\(action)完成")
            if action == "同步" { lastSync = Date() }
            addHistory(action: action, success: true, duration: duration, summary: "完成")
            if action == "同步" {
                let recovered = lastRunFailed
                lastRunFailed = false
                dispatchCompletionNotifications(success: true, recovered: recovered)
            }
        } else {
            runState = .failure
            statusText = "\(action)失败"
            appendLog("\(action)失败，退出码 \(code)", level: .error)
            addHistory(
                action: action, success: false, duration: duration,
                summary: "退出码 \(code)"
            )
            if action == "同步" {
                lastRunFailed = true
                dispatchCompletionNotifications(success: false, recovered: false)
            }
        }
        persistRuntimeState()
    }

    private func addHistory(
        action: String,
        success: Bool,
        duration: TimeInterval,
        summary: String
    ) {
        history.insert(
            SyncHistoryEntry(
                date: Date(), action: action, success: success, duration: duration,
                ipv4: detectedIPv4, ipv6: detectedIPv6,
                changes: currentRunChanges, summary: summary
            ),
            at: 0
        )
        if history.count > 100 { history.removeLast(history.count - 100) }
    }

    private func dispatchCompletionNotifications(success: Bool, recovered: Bool) {
        let settings = config.notifications
        let v4Changed = !addressesBeforeRun.v4.isEmpty
            && addressesBeforeRun.v4 != detectedIPv4 && !detectedIPv4.isEmpty
        let v6Changed = !addressesBeforeRun.v6.isEmpty
            && addressesBeforeRun.v6 != detectedIPv6 && !detectedIPv6.isEmpty
        if settings.on_ip_change, v4Changed || v6Changed {
            var parts: [String] = []
            if v4Changed { parts.append("IPv4：\(addressesBeforeRun.v4) → \(detectedIPv4)") }
            if v6Changed { parts.append("IPv6：\(addressesBeforeRun.v6) → \(detectedIPv6)") }
            sendNotification(title: "公网 IP 已变化", body: parts.joined(separator: "\n"))
        }
        if !success, settings.on_failure {
            sendNotification(
                title: "Cloudflare DDNS 同步失败",
                body: currentRunChanges.last ?? "请打开运行日志查看详细错误"
            )
            return
        }
        if success, recovered, settings.on_recovery {
            sendNotification(title: "Cloudflare DDNS 已恢复", body: "最新一次同步已成功完成")
        }
    }

    func sendTestNotification() {
        do {
            try validateConfiguration(requiresToken: false)
            try persistCredentialChanges()
            sendNotification(title: "Cloudflare DDNS 测试通知", body: "通知渠道配置正常")
        } catch {
            appendLog("无法发送测试通知：\(error.localizedDescription)", level: .error)
        }
    }

    private func sendNotification(title: String, body: String) {
        let settings = config.notifications
        if settings.local_enabled {
            let center = UNUserNotificationCenter.current()
            center.requestAuthorization(options: [.alert, .sound]) { [weak self] granted, error in
                if let error {
                    guard let model = self else { return }
                    Task { @MainActor in
                        model.appendLog("申请通知权限失败：\(error.localizedDescription)", level: .warning)
                    }
                    return
                }
                guard granted else { return }
                let content = UNMutableNotificationContent()
                content.title = title
                content.body = body
                content.sound = .default
                center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
            }
        }

        if settings.webhook_enabled, let url = URL(string: settings.webhook_url) {
            sendJSON(
                url: url,
                document: ["title": title, "message": body, "source": applicationName],
                bearer: notificationSecrets.webhookBearer,
                label: "Webhook"
            )
        }
        if settings.bark_enabled,
           let url = URL(string: settings.bark_server)?.appendingPathComponent("push") {
            sendJSON(
                url: url,
                document: [
                    "device_key": notificationSecrets.barkKey,
                    "title": title,
                    "body": body,
                    "group": applicationName,
                ],
                label: "Bark"
            )
        }
        if settings.gotify_enabled,
           var components = URLComponents(string: settings.gotify_server + "/message") {
            components.queryItems = [URLQueryItem(name: "token", value: notificationSecrets.gotifyToken)]
            if let url = components.url {
                sendJSON(
                    url: url,
                    document: ["title": title, "message": body, "priority": 5],
                    label: "Gotify"
                )
            }
        }
        if settings.telegram_enabled,
           let url = URL(string: "https://api.telegram.org/bot\(notificationSecrets.telegramBotToken)/sendMessage") {
            sendJSON(
                url: url,
                document: ["chat_id": settings.telegram_chat_id, "text": "\(title)\n\(body)"],
                label: "Telegram"
            )
        }
    }

    private func sendJSON(
        url: URL,
        document: [String: Any],
        bearer: String = "",
        label: String
    ) {
        guard JSONSerialization.isValidJSONObject(document) else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if !bearer.isEmpty {
            request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
        }
        request.httpBody = try? JSONSerialization.data(withJSONObject: document)
        URLSession.shared.dataTask(with: request) { [weak self] _, response, error in
            let status = (response as? HTTPURLResponse)?.statusCode
            guard error != nil || status.map({ !(200...299).contains($0) }) == true else { return }
            let detail = error?.localizedDescription ?? "HTTP \(status ?? 0)"
            guard let model = self else { return }
            Task { @MainActor in
                model.appendLog("\(label) 通知发送失败：\(detail)", level: .warning)
            }
        }.resume()
    }

    // MARK: Scheduler

    private func startConnectivityMonitoring() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            let available = path.status == .satisfied
            guard let model = self else { return }
            Task { @MainActor in
                if model.hasObservedNetworkPath,
                   available, !model.networkWasAvailable, model.schedulerEnabled {
                    model.appendLog("网络连接已恢复，准备立即同步")
                    model.requestImmediateScheduledSync()
                }
                model.hasObservedNetworkPath = true
                model.networkWasAvailable = available
            }
        }
        pathMonitor.start(queue: DispatchQueue(label: "io.github.xzygreen.direct-cloudflare-ddns.network"))
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            guard let model = self else { return }
            Task { @MainActor in
                guard model.schedulerEnabled else { return }
                model.appendLog("系统已唤醒，准备检查公网 IP")
                model.requestImmediateScheduledSync()
            }
        }
    }

    func setScheduler(_ enabled: Bool) {
        if enabled {
            startScheduler(runImmediately: true)
        } else {
            stopScheduler()
        }
    }

    private func requestImmediateScheduledSync() {
        nextSync = Date()
        if usingBackgroundAgent {
            do {
                try FileManager.default.createDirectory(
                    at: supportDirectory, withIntermediateDirectories: true
                )
                try Data(String(Date().timeIntervalSince1970).utf8)
                    .write(to: syncRequestURL, options: .atomic)
            } catch {
                appendLog("无法唤醒后台助手：\(error.localizedDescription)", level: .warning)
            }
        } else {
            tick()
        }
    }

    private func startScheduler(runImmediately: Bool) {
        do {
            try validateConfiguration(requiresToken: true)
            // Token 文本一旦变化必须先写入钥匙串，确保 GUI 与 Agent 使用同一凭据。
            try persistCredentialChanges()
            try saveConfiguration(report: false, persistCredentials: false)
        } catch {
            schedulerEnabled = false
            UserDefaults.standard.set(false, forKey: "schedulerEnabled")
            _ = setBackgroundAgent(enabled: false)
            usingBackgroundAgent = false
            appendLog("无法启动定时同步：\(error.localizedDescription)", level: .error)
            return
        }
        let interval = TimeInterval(config.interval_seconds)
        nextSync = Date().addingTimeInterval(interval)
        schedulerEnabled = true
        UserDefaults.standard.set(true, forKey: "schedulerEnabled")
        var backgroundAccessReady = false
        do {
            backgroundAccessReady = try KeychainStore.prepareBackgroundAgentAccess(
                token: token,
                force: runImmediately
            )
        } catch {
            appendLog(
                "后台助手无法读取 Token，已回退到 App 内定时同步：\(error.localizedDescription)",
                level: .warning
            )
        }
        usingBackgroundAgent = backgroundAccessReady && setBackgroundAgent(enabled: true)
        // 授权失败或待系统批准时保留注册项，不要注销一个原本仍可工作的助手。

        // A 1-second poll drives the countdown and, unlike a long repeating timer,
        // notices immediately after a sleep/wake that the deadline has passed.
        tickTimer?.invalidate()
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            guard let model = self else { return }
            Task { @MainActor in model.tick() }
        }
        timer.tolerance = 0.25
        RunLoop.main.add(timer, forMode: .common)
        tickTimer = timer

        if activity == nil {
            activity = ProcessInfo.processInfo.beginActivity(
                options: .background,
                reason: "Cloudflare DDNS scheduled synchronization"
            )
        }
        statusText = "定时同步已启动"
        appendLog(
            usingBackgroundAgent
                ? "后台同步助手已启动，退出主 App 后仍会按\(intervalDescription)运行"
                : "后台助手不可用，已使用 App 内定时同步（\(intervalDescription)执行一次）",
            level: usingBackgroundAgent ? .app : .warning
        )
        if runImmediately {
            if usingBackgroundAgent {
                requestImmediateScheduledSync()
            } else {
                syncNow()
            }
        }
    }

    private func tick() {
        currentTime = Date()
        agentPollTick += 1
        if usingBackgroundAgent, agentPollTick % 5 == 0 { refreshAgentStatus() }
        guard schedulerEnabled, let due = nextSync, currentTime >= due else { return }
        nextSync = Date().addingTimeInterval(TimeInterval(config.interval_seconds))
        if usingBackgroundAgent {
            refreshAgentStatus()
            return
        }
        guard !isRunning else { return }
        syncNow()
    }

    private func stopScheduler() {
        tickTimer?.invalidate()
        tickTimer = nil
        nextSync = nil
        schedulerEnabled = false
        UserDefaults.standard.set(false, forKey: "schedulerEnabled")
        _ = setBackgroundAgent(enabled: false)
        usingBackgroundAgent = false
        if let activity {
            ProcessInfo.processInfo.endActivity(activity)
            self.activity = nil
        }
        statusText = "定时同步已停止"
        appendLog("定时同步已停止")
    }

    private func setBackgroundAgent(enabled: Bool) -> Bool {
        guard #available(macOS 13.0, *) else { return false }
        let plist = Bundle.main.bundleURL.appendingPathComponent(
            "Contents/Library/LaunchAgents/io.github.xzygreen.direct-cloudflare-ddns.agent.plist"
        )
        guard FileManager.default.fileExists(atPath: plist.path) else { return false }
        let service = SMAppService.agent(
            plistName: "io.github.xzygreen.direct-cloudflare-ddns.agent.plist"
        )
        do {
            if enabled {
                if service.status == .notRegistered { try service.register() }
                if service.status == .requiresApproval {
                    appendLog(
                        "后台助手等待系统批准，请到“系统设置 → 通用 → 登录项”允许后重试",
                        level: .warning
                    )
                    return false
                }
            } else if service.status != .notRegistered {
                try service.unregister()
            }
            return enabled && service.status == .enabled
        } catch {
            appendLog(
                "后台同步助手\(enabled ? "启动" : "停止")失败：\(error.localizedDescription)",
                level: .warning
            )
            return false
        }
    }

    private func refreshAgentStatus() {
        let url = supportDirectory.appendingPathComponent("agent-status.json")
        guard let data = try? Data(contentsOf: url),
              let status = try? JSONDecoder().decode(AgentStatus.self, from: data),
              status.timestamp != lastAgentStatusTimestamp else { return }
        lastAgentStatusTimestamp = status.timestamp
        UserDefaults.standard.set(status.timestamp, forKey: "lastAgentStatusTimestamp")
        currentRunChanges = []
        addressesBeforeRun = (detectedIPv4, detectedIPv6)
        for line in status.events ?? [] {
            ingestBackendLine(line)
        }
        for line in status.output.components(separatedBy: .newlines)
            where !line.hasPrefix("@@DDNS_EVENT@@") {
            ingestBackendLine(line)
        }
        if let error = status.error, !error.isEmpty {
            appendLog("后台助手：\(error)", level: .error)
        }
        let formatter = ISO8601DateFormatter()
        let date = formatter.date(from: status.timestamp) ?? Date()
        let duration = status.started_at.flatMap(formatter.date(from:)).map {
            date.timeIntervalSince($0)
        } ?? 0
        let skipped = status.skipped == true
        if status.success { lastSync = date }
        addHistory(
            action: "后台同步", success: status.success || skipped, duration: duration,
            summary: skipped ? "已跳过：实例忙" : (status.success ? "完成" : "退出码 \(status.exit_code)")
        )
        if !skipped {
            lastRunFailed = !status.success
        }
        persistRuntimeState()
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        guard #available(macOS 13.0, *) else {
            appendLog("登录时启动需要 macOS 13 或更高版本", level: .warning)
            return
        }
        do {
            if enabled {
                if SMAppService.mainApp.status != .enabled {
                    try SMAppService.mainApp.register()
                }
            } else if SMAppService.mainApp.status != .notRegistered {
                try SMAppService.mainApp.unregister()
            }
            launchAtLoginEnabled = SMAppService.mainApp.status == .enabled
            appendLog(launchAtLoginEnabled ? "已启用登录时启动" : "已关闭登录时启动")
        } catch {
            launchAtLoginEnabled = SMAppService.mainApp.status == .enabled
            appendLog(
                "修改登录启动设置失败：\(error.localizedDescription)。请先把 App 移到“应用程序”目录。",
                level: .error
            )
        }
    }

    func addRecord() {
        let zone = config.cloudflare.zone_name
        config.records.append(
            DNSRecord(name: zone.isEmpty ? "home.example.com" : "home.\(zone)")
        )
    }

    func copyToPasteboard(_ text: String) {
        guard !text.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        appendLog("已复制 \(text)")
    }

    func checkForUpdates(reportMissingFeed: Bool = true) {
        guard let feed = Bundle.main.object(forInfoDictionaryKey: "DirectDDNSUpdateFeedURL") as? String,
              let url = URL(string: feed), !feed.isEmpty else {
            updateStatus = "当前构建未配置更新源"
            if reportMissingFeed { appendLog(updateStatus, level: .warning) }
            return
        }
        updateStatus = "正在检查更新…"
        URLSession.shared.dataTask(with: url) { [weak self] data, _, error in
            guard let model = self else { return }
            Task { @MainActor in
                if let error {
                    model.updateStatus = "检查更新失败"
                    model.appendLog("检查更新失败：\(error.localizedDescription)", level: .warning)
                    return
                }
                guard let data,
                      let manifest = try? JSONDecoder().decode(UpdateManifest.self, from: data) else {
                    model.updateStatus = "更新清单格式无效"
                    model.appendLog(model.updateStatus, level: .warning)
                    return
                }
                let current = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString")
                    as? String ?? "0"
                if manifest.version.compare(current, options: .numeric) == .orderedDescending {
                    model.updateStatus = "发现新版本 \(manifest.version)"
                    model.appendLog(
                        "\(model.updateStatus)：\(manifest.notes ?? manifest.url)；SHA-256 \(manifest.sha256)"
                    )
                } else {
                    model.updateStatus = "已是最新版本（\(current)）"
                    model.appendLog(model.updateStatus)
                }
                UserDefaults.standard.set(Date(), forKey: "lastUpdateCheck")
            }
        }.resume()
    }

    private func checkForUpdatesIfDue() {
        let last = UserDefaults.standard.object(forKey: "lastUpdateCheck") as? Date ?? .distantPast
        if Date().timeIntervalSince(last) >= 86_400 {
            checkForUpdates(reportMissingFeed: false)
        }
    }
}


// MARK: - Reusable views

struct GlyphBadge: View {
    let symbol: String
    var tint: Color = Brand.blue
    var size: CGFloat = 30

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
            .fill(tint.opacity(0.11))
            .frame(width: size, height: size)
            .overlay(
                RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                    .strokeBorder(tint.opacity(0.18), lineWidth: 0.8)
            )
            .overlay(
                Image(systemName: symbol)
                    .font(.system(size: size * 0.48, weight: .semibold))
                    .foregroundStyle(tint)
            )
            .shadow(color: tint.opacity(0.10), radius: size * 0.12, y: size * 0.06)
    }
}


struct Card<Content: View>: View {
    var title: String? = nil
    var symbol: String? = nil
    var tint: Color = Brand.blue
    var subtitle: String? = nil
    var trailingBadge: String? = nil
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let title {
                HStack(spacing: 11) {
                    if let symbol {
                        GlyphBadge(symbol: symbol, tint: tint, size: 28)
                    }
                    VStack(alignment: .leading, spacing: 2) {
                        Text(title)
                            .font(.system(.headline, weight: .semibold))
                        if let subtitle {
                            Text(subtitle)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Spacer(minLength: 8)
                    if let trailingBadge {
                        Text(trailingBadge)
                            .font(.caption2.weight(.medium))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(Capsule().fill(tint.opacity(0.12)))
                            .foregroundStyle(tint)
                    }
                }
            }
            content
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: Brand.cardRadius, style: .continuous)
                .fill(Brand.surface)
        )
        .overlay(
            RoundedRectangle(cornerRadius: Brand.cardRadius, style: .continuous)
                .strokeBorder(Brand.border, lineWidth: 1)
        )
        .shadow(color: .black.opacity(0.045), radius: 10, y: 3)
    }
}


struct SpinningGlyph: View {
    let symbol: String
    let active: Bool
    @State private var angle: Double = 0

    private var spinAnimation: Animation {
        .linear(duration: 1.0).repeatForever(autoreverses: false)
    }

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 11, weight: .bold))
            .rotationEffect(.degrees(angle))
            .onAppear {
                guard active else { return }
                withAnimation(spinAnimation) { angle = 360 }
            }
            .onChange(of: active) { isActive in
                if isActive {
                    angle = 0
                    withAnimation(spinAnimation) { angle = 360 }
                } else {
                    withAnimation(.easeOut(duration: 0.2)) { angle = 0 }
                }
            }
    }
}


struct HeroSecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 12)
            .frame(maxWidth: .infinity, minHeight: 30)
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(Color.white.opacity(configuration.isPressed ? 0.18 : 0.09))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.22), lineWidth: 0.8)
            )
            .foregroundStyle(.white)
            .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}


struct StatusPill: View {
    let state: RunState
    let text: String

    var body: some View {
        HStack(spacing: 6) {
            if state == .running {
                SpinningGlyph(symbol: state.symbol, active: true)
            } else {
                Circle()
                    .fill(state.tint)
                    .frame(width: 7, height: 7)
                    .shadow(color: state.tint.opacity(0.32), radius: 3, y: 1)
            }
            Text(text)
                .font(.caption.weight(.semibold))
                .lineLimit(1)
        }
        .foregroundStyle(state.tint)
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(Capsule().fill(state.tint.opacity(0.14)))
        .overlay(Capsule().strokeBorder(state.tint.opacity(0.20), lineWidth: 0.8))
    }
}


struct AddressChip: View {
    let label: String
    let symbol: String
    let value: String
    let tint: Color
    var onCopy: () -> Void

    @State private var justCopied = false

    var body: some View {
        HStack(spacing: 12) {
            GlyphBadge(symbol: symbol, tint: tint, size: 34)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(label)
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                    if !value.isEmpty {
                        Circle()
                            .fill(tint)
                            .frame(width: 5, height: 5)
                    }
                }
                Text(value.isEmpty ? "尚未检测" : value)
                    .font(.system(.body, design: .monospaced).weight(.semibold))
                    .foregroundStyle(value.isEmpty ? Color.secondary : Color.primary)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 4)
            if !value.isEmpty {
                Button {
                    onCopy()
                    justCopied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) {
                        justCopied = false
                    }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: justCopied ? "checkmark" : "doc.on.doc")
                            .font(.system(size: 11, weight: .semibold))
                        if justCopied {
                            Text("已复制")
                                .font(.caption2.weight(.medium))
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(
                        RoundedRectangle(cornerRadius: 6, style: .continuous)
                            .fill(justCopied ? Brand.mint.opacity(0.18) : Color.primary.opacity(0.06))
                    )
                    .foregroundStyle(justCopied ? Brand.mint : Color.secondary)
                }
                .buttonStyle(.plain)
                .help("复制到剪贴板")
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(tint.opacity(0.06))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .strokeBorder(tint.opacity(0.14), lineWidth: 0.8)
        )
    }
}


struct TypeChip: View {
    let label: String
    @Binding var isOn: Bool

    var body: some View {
        Button {
            withAnimation(.spring(response: 0.25, dampingFraction: 0.7)) {
                isOn.toggle()
            }
        } label: {
            Text(label)
                .font(.system(.caption, design: .monospaced).weight(.bold))
                .frame(minWidth: 44)
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(
                    Capsule().fill(
                        isOn ? AnyShapeStyle(Brand.badge(label == "A" ? Brand.blue : Brand.mint))
                             : AnyShapeStyle(Color.primary.opacity(0.06))
                    )
                )
                .foregroundStyle(isOn ? Color.white : Color.secondary)
                .overlay(
                    Capsule()
                        .strokeBorder(isOn ? Color.white.opacity(0.2) : Color.primary.opacity(0.08), lineWidth: 0.8)
                )
        }
        .buttonStyle(.plain)
        .help(label == "A" ? "同步 IPv4 地址 (A 记录)" : "同步 IPv6 地址 (AAAA 记录)")
    }
}


struct PageHeader: View {
    let title: String
    let subtitle: String
    let symbol: String
    var tint: Color = Brand.blue

    var body: some View {
        HStack(spacing: 12) {
            GlyphBadge(symbol: symbol, tint: tint, size: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.title2.weight(.semibold))
                Text(subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }
}


// MARK: - Pages

struct OverviewPage: View {
    @EnvironmentObject private var model: AppModel
    @Binding var selection: SidebarSection?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                heroCard

                if let error = model.configurationLoadError {
                    configurationErrorBanner(error)
                }

                if !model.hasToken {
                    warningBanner
                }

                HStack(spacing: 14) {
                    AddressChip(
                        label: "公网 IPv4",
                        symbol: "4.circle.fill",
                        value: model.detectedIPv4,
                        tint: Brand.blue
                    ) { model.copyToPasteboard(model.detectedIPv4) }
                    AddressChip(
                        label: "公网 IPv6",
                        symbol: "6.circle.fill",
                        value: model.detectedIPv6,
                        tint: Brand.mint
                    ) { model.copyToPasteboard(model.detectedIPv6) }
                }

                Card(title: "自动化设置", symbol: "clock.arrow.2.circlepath", tint: Brand.orange) {
                    VStack(spacing: 12) {
                        Toggle(isOn: Binding(
                            get: { model.schedulerEnabled },
                            set: { model.setScheduler($0) }
                        )) {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text("定时同步").font(.body.weight(.medium))
                                    if model.schedulerEnabled {
                                        Text(model.schedulerDescription)
                                            .font(.caption2.weight(.medium))
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(Capsule().fill(Brand.orange.opacity(0.15)))
                                            .foregroundStyle(Brand.orange)
                                    }
                                }
                                Text(
                                    model.usingBackgroundAgent
                                        ? "后台助手正在运行；退出主 App 后仍会\(model.intervalDescription)同步"
                                        : "\(model.intervalDescription)检查一次公网 IP 并按需更新"
                                )
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.switch)

                        Divider()

                        Toggle(isOn: Binding(
                            get: { model.launchAtLoginEnabled },
                            set: { model.setLaunchAtLogin($0) }
                        )) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("登录时启动").font(.body.weight(.medium))
                                Text("随 macOS 启动并在后台静默同步（需将 App 放入“应用程序”目录）")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.switch)
                    }
                }

                Card(
                    title: "记录概览",
                    symbol: "list.bullet.rectangle",
                    tint: Brand.mint,
                    subtitle: "\(model.config.records.count) 条记录 · 区域 \(zoneLabel)",
                    trailingBadge: zoneLabel
                ) {
                    if model.config.records.isEmpty {
                        HStack(spacing: 8) {
                            Image(systemName: "info.circle")
                                .foregroundStyle(.secondary)
                            Text("尚未添加 DNS 记录，请前往“DNS 记录”页添加")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Button("前往添加") {
                                selection = .records
                            }
                            .controlSize(.small)
                        }
                        .padding(.vertical, 6)
                    } else {
                        VStack(spacing: 8) {
                            ForEach(model.config.records) { record in
                                HStack(spacing: 10) {
                                    Image(systemName: "globe")
                                        .foregroundStyle(Brand.blue)
                                        .font(.system(size: 14))
                                    Text(record.name.isEmpty ? "（未填写域名）" : record.name)
                                        .font(.system(.body, design: .monospaced))
                                    Spacer()
                                    ForEach(record.types, id: \.self) { type in
                                        Text(type)
                                            .font(.caption2.weight(.bold))
                                            .padding(.horizontal, 7)
                                            .padding(.vertical, 3)
                                            .background(
                                                Capsule().fill(
                                                    type == "A" ? Brand.blue.opacity(0.15) : Brand.mint.opacity(0.15)
                                                )
                                            )
                                            .foregroundStyle(type == "A" ? Brand.blue : Brand.mint)
                                    }
                                    if record.proxied {
                                        HStack(spacing: 3) {
                                            Image(systemName: "shield.lefthalf.filled")
                                                .font(.system(size: 11))
                                            Text("已代理")
                                                .font(.caption2.weight(.semibold))
                                        }
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 3)
                                        .background(Capsule().fill(Brand.orange.opacity(0.15)))
                                        .foregroundStyle(Brand.orange)
                                        .help("已开启 Cloudflare 代理（CDN加速与隐藏源站）")
                                    }
                                    Text(record.ttl == 1 ? "TTL 自动" : "TTL \(record.ttl)s")
                                        .font(.caption.monospacedDigit())
                                        .foregroundStyle(.secondary)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(
                                            RoundedRectangle(cornerRadius: 4)
                                                .fill(Color.primary.opacity(0.04))
                                        )
                                }
                                if record.id != model.config.records.last?.id {
                                    Divider()
                                }
                            }
                        }
                    }
                }
            }
            .padding(Brand.pagePadding)
        }
    }

    private var zoneLabel: String {
        let zone = model.config.cloudflare.zone_name
        if !zone.isEmpty { return zone }
        return model.config.cloudflare.zone_id == nil ? "未设置" : "按 Zone ID"
    }

    private var heroCard: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(alignment: .top, spacing: 14) {
                Image(nsImage: NSApplication.shared.applicationIconImage)
                    .resizable()
                    .frame(width: 50, height: 50)
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .strokeBorder(Color.white.opacity(0.25), lineWidth: 1)
                    )
                    .shadow(color: .black.opacity(0.25), radius: 6, y: 3)

                VStack(alignment: .leading, spacing: 3) {
                    Text(applicationName)
                        .font(.title2.weight(.semibold))
                        .foregroundStyle(.white)
                    Text(applicationTagline)
                        .font(.callout)
                        .foregroundStyle(.white.opacity(0.85))
                }

                Spacer()

                VStack(alignment: .trailing, spacing: 6) {
                    StatusPill(state: model.runState, text: model.statusText)
                        .colorScheme(.dark)
                    if model.schedulerEnabled {
                        Text(model.schedulerDescription)
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.white.opacity(0.85))
                    }
                    Text("上次同步：\(model.lastSyncDescription)")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.white.opacity(0.65))
                }
            }

            HStack(spacing: 10) {
                Button {
                    model.syncNow()
                } label: {
                    Label("立即同步", systemImage: "arrow.triangle.2.circlepath")
                        .font(.body.weight(.semibold))
                        .frame(maxWidth: .infinity)
                }
                .controlSize(.large)
                .buttonStyle(.borderedProminent)
                .tint(.white)
                .foregroundStyle(Brand.ink)
                .disabled(model.isRunning)

                Button {
                    model.checkIP()
                } label: {
                    Label("检测公网 IP", systemImage: "dot.radiowaves.left.and.right")
                        .frame(maxWidth: .infinity)
                }
                .controlSize(.large)
                .buttonStyle(HeroSecondaryButtonStyle())
                .disabled(model.isRunning)

                Button {
                    model.dryRun()
                } label: {
                    Label("演练", systemImage: "wand.and.stars")
                        .frame(maxWidth: .infinity)
                }
                .controlSize(.large)
                .buttonStyle(HeroSecondaryButtonStyle())
                .disabled(model.isRunning)

                if model.isRunning {
                    Button(role: .destructive) {
                        model.cancelRun()
                    } label: {
                        Label("停止", systemImage: "stop.fill")
                    }
                    .controlSize(.large)
                    .buttonStyle(.bordered)
                    .tint(Brand.rose)
                }
            }
        }
        .padding(22)
        .background(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(Brand.hero)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .strokeBorder(Color.white.opacity(0.18), lineWidth: 1)
        )
        .shadow(color: Brand.ink.opacity(0.26), radius: 16, y: 7)
    }

    private var warningBanner: some View {
        HStack(spacing: 12) {
            GlyphBadge(symbol: "key.horizontal.fill", tint: Brand.orange, size: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text("尚未填写 API Token").font(.callout.weight(.semibold))
                Text("在“Cloudflare”页填入具备 Zone:Read 与 DNS:Edit 权限的 Token 后才能同步")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("去填写 Token") {
                selection = .cloudflare
            }
            .buttonStyle(.borderedProminent)
            .tint(Brand.orange)
            .controlSize(.small)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(Brand.orange.opacity(0.10))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .strokeBorder(Brand.orange.opacity(0.25), lineWidth: 1)
        )
    }

    private func configurationErrorBanner(_ error: String) -> some View {
        HStack(spacing: 12) {
            GlyphBadge(symbol: "exclamationmark.triangle.fill", tint: Brand.rose, size: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text("配置文件无法载入，已锁定写入").font(.callout.weight(.semibold))
                Text(error).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("恢复最近备份") {
                model.restoreLatestConfigurationBackup()
            }
            .controlSize(.small)
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(Brand.rose.opacity(0.10))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .strokeBorder(Brand.rose.opacity(0.25), lineWidth: 1)
        )
    }
}


struct CloudflarePage: View {
    @EnvironmentObject private var model: AppModel
    @State private var revealToken = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                PageHeader(
                    title: "Cloudflare",
                    subtitle: "API 凭据与区域配置",
                    symbol: "cloud.fill",
                    tint: Brand.orange
                )

                Card(
                    title: "API Token",
                    symbol: "key.fill",
                    tint: Brand.orange,
                    subtitle: "安全存入 macOS 钥匙串，不会明文写入配置文件",
                    trailingBadge: model.hasToken ? "已配置" : "未设置"
                ) {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 8) {
                            Group {
                                if revealToken {
                                    TextField("粘贴 Cloudflare API Token", text: $model.token)
                                } else {
                                    SecureField("粘贴 Cloudflare API Token", text: $model.token)
                                }
                            }
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))

                            Button {
                                revealToken.toggle()
                            } label: {
                                Image(systemName: revealToken ? "eye.slash" : "eye")
                                    .frame(width: 18)
                            }
                            .buttonStyle(.borderless)
                            .help(revealToken ? "隐藏 Token" : "显示 Token")

                            Button {
                                if let text = NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty {
                                    model.token = text
                                }
                            } label: {
                                Image(systemName: "arrow.right.doc.on.clipboard")
                                    .frame(width: 18)
                            }
                            .buttonStyle(.borderless)
                            .help("从剪贴板粘贴")
                        }

                        HStack(spacing: 6) {
                            Image(systemName: "checkmark.shield.fill")
                                .foregroundStyle(Brand.mint)
                                .font(.caption)
                            Text("所需权限：区域 · 区域 · 读取；区域 · DNS · 编辑")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                Card(
                    title: "自动发现与连接测试",
                    symbol: "sparkle.magnifyingglass",
                    tint: Brand.mint,
                    subtitle: "验证 Token 权限，并从 Cloudflare 导入区域和已有记录"
                ) {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(spacing: 10) {
                            Button {
                                model.discoverCloudflare()
                            } label: {
                                Label("发现可访问区域", systemImage: "sparkle.magnifyingglass")
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(Brand.mint)
                            .disabled(model.isRunning || !model.hasToken)

                            Button {
                                model.testConnection()
                            } label: {
                                Label("测试当前配置", systemImage: "bolt.horizontal.fill")
                            }
                            .disabled(model.isRunning || !model.hasToken)

                            Spacer()
                        }

                        if !model.discoveredZones.isEmpty {
                            Divider()

                            HStack {
                                Text("选择区域：").font(.callout.weight(.medium))
                                Picker("", selection: Binding(
                                    get: { model.config.cloudflare.zone_id ?? "" },
                                    set: { id in
                                        if let zone = model.discoveredZones.first(where: { $0.id == id }) {
                                            model.selectDiscoveredZone(zone)
                                        }
                                    }
                                )) {
                                    Text("请选择 Cloudflare 区域").tag("")
                                    ForEach(model.discoveredZones) { zone in
                                        Text("\(zone.name)\(zone.status.map { " · \($0)" } ?? "")").tag(zone.id)
                                    }
                                }
                                .pickerStyle(.menu)
                            }
                        }

                        if !model.discoveredRecords.isEmpty {
                            Divider()

                            VStack(alignment: .leading, spacing: 8) {
                                Text("发现的已有 A/AAAA 记录").font(.caption.weight(.semibold)).foregroundStyle(.secondary)

                                ForEach(model.discoveredRecords) { record in
                                    HStack(spacing: 10) {
                                        Text(record.type)
                                            .font(.caption2.bold())
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(
                                                Capsule().fill(
                                                    record.type == "A" ? Brand.blue.opacity(0.15) : Brand.mint.opacity(0.15)
                                                )
                                            )
                                            .foregroundStyle(record.type == "A" ? Brand.blue : Brand.mint)
                                            .frame(width: 50)

                                        Text(record.name)
                                            .font(.system(.body, design: .monospaced))

                                        Spacer()

                                        Text(record.content ?? "")
                                            .font(.caption2.monospaced())
                                            .foregroundStyle(.secondary)

                                        Button(model.isRecordImported(record) ? "已添加" : "添加为同步记录") {
                                            model.importDiscoveredRecord(record)
                                        }
                                        .controlSize(.small)
                                        .disabled(model.isRecordImported(record))
                                    }
                                    .padding(8)
                                    .background(
                                        RoundedRectangle(cornerRadius: 8)
                                            .fill(Color.primary.opacity(0.03))
                                    )
                                }
                            }
                        }
                    }
                }

                Card(
                    title: "区域配置",
                    symbol: "globe.asia.australia.fill",
                    tint: Brand.blue,
                    subtitle: "填写主域名即可，Zone ID 留空时会自动查询"
                ) {
                    Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 12) {
                        GridRow {
                            Text("区域名 (Zone)")
                                .font(.callout.weight(.medium))
                                .gridColumnAlignment(.trailing)
                            TextField("例如 example.com", text: $model.config.cloudflare.zone_name)
                                .textFieldStyle(.roundedBorder)
                        }
                        GridRow {
                            Text("Zone ID")
                                .font(.callout.weight(.medium))
                                .gridColumnAlignment(.trailing)
                            TextField(
                                "可留空（保存后将自动解析）",
                                text: Binding(
                                    get: { model.config.cloudflare.zone_id ?? "" },
                                    set: { model.config.cloudflare.zone_id = $0.isEmpty ? nil : $0 }
                                )
                            )
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                        }
                    }
                }

                Card(title: "行为选项", symbol: "slider.horizontal.3", tint: Brand.purple) {
                    VStack(alignment: .leading, spacing: 12) {
                        Toggle(isOn: $model.config.cloudflare.create_missing_records) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("自动创建缺失的记录").font(.body.weight(.medium))
                                Text("若 Cloudflare 上尚不存在指定的 DNS 记录，自动新建该记录")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.switch)

                        Divider()

                        Toggle(isOn: $model.config.cloudflare.bypass_proxy) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("调用 Cloudflare API 时绕过系统代理").font(.body.weight(.medium))
                                Text("默认关闭：API 请求沿用系统网络代理设置")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.switch)
                    }
                }
            }
            .padding(Brand.pagePadding)
        }
    }
}


struct RecordCard: View {
    @Binding var record: DNSRecord
    let index: Int
    let onDelete: () -> Void

    private func typeBinding(_ type: String) -> Binding<Bool> {
        Binding(
            get: { record.types.contains(type) },
            set: { enabled in
                if enabled && !record.types.contains(type) {
                    record.types.append(type)
                } else if !enabled {
                    record.types.removeAll(where: { $0 == type })
                }
            }
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Text("#\(index + 1)")
                    .font(.caption.weight(.bold).monospacedDigit())
                    .foregroundStyle(.white)
                    .frame(width: 32, height: 26)
                    .background(
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(Brand.badge(Brand.blue))
                    )
                    .help("第 \(index + 1) 条记录")

                TextField("完整域名，如 home.example.com", text: $record.name)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))

                Button(role: .destructive, action: onDelete) {
                    Image(systemName: "trash")
                        .foregroundStyle(Brand.rose)
                }
                .buttonStyle(.borderless)
                .help("删除这条记录")
            }

            HStack(spacing: 14) {
                HStack(spacing: 6) {
                    TypeChip(label: "A", isOn: typeBinding("A"))
                    TypeChip(label: "AAAA", isOn: typeBinding("AAAA"))
                }

                Divider().frame(height: 20)

                HStack(spacing: 6) {
                    Text("TTL:").font(.caption.weight(.medium)).foregroundStyle(.secondary)
                    TextField("1", value: $record.ttl, format: .number)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 70)
                        .help("1 表示自动 TTL，其余需在 60-86400 之间")
                    if record.ttl == 1 {
                        Text("自动").font(.caption.weight(.semibold)).foregroundStyle(Brand.mint)
                    } else {
                        Text("秒").font(.caption).foregroundStyle(.secondary)
                    }
                }

                Divider().frame(height: 20)

                Toggle(isOn: $record.proxied) {
                    HStack(spacing: 4) {
                        Image(systemName: "shield.lefthalf.filled")
                            .foregroundStyle(record.proxied ? Brand.orange : .secondary)
                        Text("Cloudflare 代理")
                            .font(.callout)
                    }
                }
                .toggleStyle(.checkbox)
                .help("开启后隐藏真实 IP；SSH、VPN 等非 HTTP 服务请保持关闭")

                Spacer()
            }

            HStack(spacing: 8) {
                Image(systemName: "text.bubble")
                    .foregroundStyle(.secondary)
                    .font(.caption)
                TextField(
                    "备注说明（可选）",
                    text: Binding(
                        get: { record.comment ?? "" },
                        set: { record.comment = $0.isEmpty ? nil : $0 }
                    )
                )
                .textFieldStyle(.roundedBorder)
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: Brand.cardRadius, style: .continuous)
                .fill(Brand.surface)
        )
        .overlay(
            RoundedRectangle(cornerRadius: Brand.cardRadius, style: .continuous)
                .strokeBorder(Brand.border, lineWidth: 1)
        )
        .shadow(color: .black.opacity(0.04), radius: 10, y: 3)
    }
}


struct RecordsPage: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                PageHeader(
                    title: "DNS 记录",
                    subtitle: "需要跟随公网 IP 变化自动同步的主机名",
                    symbol: "list.bullet.rectangle.portrait.fill",
                    tint: Brand.mint
                )

                if model.config.records.isEmpty {
                    Card {
                        VStack(spacing: 12) {
                            Image(systemName: "globe.badge.chevron.backward")
                                .font(.system(size: 40))
                                .foregroundStyle(Brand.mint.opacity(0.7))
                            Text("尚未添加任何 DNS 记录").font(.headline)
                            Text("点击下方“添加记录”按钮添加需要解析的域名")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 24)
                    }
                }

                ForEach(Array($model.config.records.enumerated()), id: \.element.id) { pair in
                    RecordCard(record: pair.element, index: pair.offset) {
                        let target = pair.element.wrappedValue.id
                        model.config.records.removeAll(where: { $0.id == target })
                    }
                }

                HStack {
                    Button(action: model.addRecord) {
                        Label("添加记录", systemImage: "plus.circle.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Brand.mint)
                    .controlSize(.large)

                    Spacer()

                    HStack(spacing: 6) {
                        Image(systemName: "info.circle")
                            .foregroundStyle(.secondary)
                        Text("TTL=1 为自动；非 Web 服务（如 SSH/VPN/游戏）请关闭代理")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.top, 4)
            }
            .padding(Brand.pagePadding)
        }
    }
}


struct ServiceListEditor: View {
    let title: String
    let symbol: String
    let tint: Color
    let defaultEndpoints: [ServiceEndpoint]
    @Binding var services: [ServiceEndpoint]

    var body: some View {
        Card(
            title: title,
            symbol: symbol,
            tint: tint,
            subtitle: "多服务共同投票共识，避免单一查询节点返回异常地址",
            trailingBadge: "\(services.count) 个来源"
        ) {
            VStack(spacing: 10) {
                ForEach($services) { $service in
                    HStack(spacing: 8) {
                        Image(systemName: "link")
                            .foregroundStyle(tint)
                            .font(.caption)
                        TextField("https://example.com", text: $service.url)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.callout, design: .monospaced))
                        Button(role: .destructive) {
                            let target = service.id
                            services.removeAll(where: { $0.id == target })
                        } label: {
                            Image(systemName: "minus.circle.fill")
                                .foregroundStyle(Brand.rose)
                        }
                        .buttonStyle(.borderless)
                        .disabled(services.count <= 1)
                        .help("删除此来源")
                    }
                }

                HStack(spacing: 12) {
                    Button {
                        services.append(ServiceEndpoint("https://"))
                    } label: {
                        Label("添加来源", systemImage: "plus.circle")
                    }
                    .buttonStyle(.borderless)

                    Button {
                        services = defaultEndpoints
                    } label: {
                        Label("恢复推荐默认", systemImage: "arrow.counterclockwise")
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)

                    Spacer()
                }
                .padding(.top, 2)
            }
        }
    }
}


struct NetworkPage: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                PageHeader(
                    title: "网络与调度",
                    subtitle: "IP 检测策略、超时控制与同步节奏",
                    symbol: "antenna.radiowaves.left.and.right",
                    tint: Brand.blue
                )

                Card(title: "调度与共识", symbol: "timer", tint: Brand.orange) {
                    Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 14) {
                        GridRow {
                            Text("同步间隔")
                                .font(.callout.weight(.medium))
                                .gridColumnAlignment(.trailing)
                            VStack(alignment: .leading, spacing: 6) {
                                HStack(spacing: 8) {
                                    TextField(
                                        "300",
                                        value: $model.config.interval_seconds,
                                        format: .number
                                    )
                                    .textFieldStyle(.roundedBorder)
                                    .frame(width: 80)
                                    Stepper("", value: $model.config.interval_seconds, in: 30...86400, step: 30)
                                        .labelsHidden()
                                    Text("秒 · 当前设置：\(model.intervalDescription)")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }

                                HStack(spacing: 6) {
                                    ForEach([60, 300, 600, 1800, 3600], id: \.self) { seconds in
                                        Button {
                                            model.config.interval_seconds = seconds
                                        } label: {
                                            Text(presetIntervalLabel(seconds))
                                                .font(.caption2.weight(.medium))
                                                .padding(.horizontal, 8)
                                                .padding(.vertical, 4)
                                                .background(
                                                    Capsule().fill(
                                                        model.config.interval_seconds == seconds
                                                            ? Brand.orange.opacity(0.2)
                                                            : Color.primary.opacity(0.05)
                                                    )
                                                )
                                                .foregroundStyle(
                                                    model.config.interval_seconds == seconds
                                                        ? Brand.orange
                                                        : Color.secondary
                                                )
                                        }
                                        .buttonStyle(.plain)
                                    }
                                }
                            }
                        }

                        GridRow {
                            Text("请求超时")
                                .font(.callout.weight(.medium))
                                .gridColumnAlignment(.trailing)
                            HStack(spacing: 8) {
                                TextField(
                                    "8",
                                    value: $model.config.request_timeout_seconds,
                                    format: .number
                                )
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 80)
                                Stepper("", value: $model.config.request_timeout_seconds, in: 1...60)
                                    .labelsHidden()
                                Text("秒（建议 5-15 秒）").font(.caption).foregroundStyle(.secondary)
                            }
                        }

                        GridRow {
                            Text("IPv4 共识")
                                .font(.callout.weight(.medium))
                                .gridColumnAlignment(.trailing)
                            HStack(spacing: 8) {
                                Stepper(
                                    value: $model.config.ip_detection.minimum_agreement.ipv4,
                                    in: 1...model.ipv4AgreementUpperBound
                                ) {
                                    Text("\(model.config.ip_detection.minimum_agreement.ipv4)")
                                        .font(.body.monospacedDigit().weight(.semibold))
                                        .frame(width: 24)
                                }
                                Text("至少 \(model.config.ip_detection.minimum_agreement.ipv4) / \(model.ipv4AgreementUpperBound) 个 IPv4 来源一致")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }

                        GridRow {
                            Text("IPv6 共识")
                                .font(.callout.weight(.medium))
                                .gridColumnAlignment(.trailing)
                            HStack(spacing: 8) {
                                Stepper(
                                    value: $model.config.ip_detection.minimum_agreement.ipv6,
                                    in: 1...model.ipv6AgreementUpperBound
                                ) {
                                    Text("\(model.config.ip_detection.minimum_agreement.ipv6)")
                                        .font(.body.monospacedDigit().weight(.semibold))
                                        .frame(width: 24)
                                }
                                Text("至少 \(model.config.ip_detection.minimum_agreement.ipv6) / \(model.ipv6AgreementUpperBound) 个 IPv6 来源一致")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }

                Card(title: "代理与安全性", symbol: "arrow.triangle.branch", tint: Brand.mint) {
                    VStack(alignment: .leading, spacing: 12) {
                        Toggle(isOn: $model.config.ip_detection.bypass_proxy) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("检测公网 IP 时绕过系统代理").font(.body.weight(.medium))
                                Text("强烈建议开启：若通过代理查询，将获取代理节点 IP 而非本机真实宽带 IP")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.switch)

                        Divider()

                        Toggle(isOn: $model.config.ip_detection.source_diagnostics) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("显示每个查询来源的耗时与成功率").font(.body.weight(.medium))
                                Text("在日志中输出各个 IP 探测 API 节点的实时响应延迟")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.switch)

                        Divider()

                        Toggle(isOn: $model.config.ip_detection.allow_insecure_http) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("允许不安全的 HTTP 查询来源").font(.body.weight(.medium))
                                Text("默认关闭：未加密 HTTP 易受中间人篡改")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.switch)

                        if model.config.ip_detection.allow_insecure_http {
                            HStack(spacing: 6) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(Brand.amber)
                                Text("HTTP 响应可能被篡改，仅建议在受信任网络中临时测试使用")
                                    .font(.caption)
                                    .foregroundStyle(Brand.amber)
                            }
                            .padding(8)
                            .background(
                                RoundedRectangle(cornerRadius: 8)
                                    .fill(Brand.amber.opacity(0.12))
                            )
                        }
                    }
                }

                ServiceListEditor(
                    title: "IPv4 查询来源",
                    symbol: "4.circle.fill",
                    tint: Brand.blue,
                    defaultEndpoints: DetectionServices().ipv4,
                    services: $model.config.ip_detection.services.ipv4
                )

                ServiceListEditor(
                    title: "IPv6 查询来源",
                    symbol: "6.circle.fill",
                    tint: Brand.mint,
                    defaultEndpoints: DetectionServices().ipv6,
                    services: $model.config.ip_detection.services.ipv6
                )

                Card {
                    HStack(spacing: 12) {
                        Image(systemName: "doc.text.fill")
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("本地配置文件路径").font(.caption.weight(.medium)).foregroundStyle(.secondary)
                            Text(model.configURL.path)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .truncationMode(.middle)
                                .lineLimit(1)
                        }
                        Spacer()
                        Button {
                            model.revealConfiguration()
                        } label: {
                            Label("在访达中显示", systemImage: "folder")
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                }
            }
            .padding(Brand.pagePadding)
        }
    }

    private func presetIntervalLabel(_ seconds: Int) -> String {
        switch seconds {
        case 60: return "1分钟"
        case 300: return "5分钟"
        case 600: return "10分钟"
        case 1800: return "30分钟"
        case 3600: return "1小时"
        default: return "\(seconds)秒"
        }
    }
}


struct NotificationsPage: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                PageHeader(
                    title: "通知",
                    subtitle: "仅在地址变更、执行失败或恢复时推送，静默无扰",
                    symbol: "bell.badge.fill",
                    tint: Brand.orange
                )

                Card(title: "触发条件", symbol: "line.3.horizontal.decrease.circle", tint: Brand.blue) {
                    VStack(alignment: .leading, spacing: 12) {
                        Toggle("公网 IP 发生变更时发送通知", isOn: $model.config.notifications.on_ip_change)
                            .toggleStyle(.switch)
                        Divider()
                        Toggle("同步执行失败时发送通知", isOn: $model.config.notifications.on_failure)
                            .toggleStyle(.switch)
                        Divider()
                        Toggle("从失败状态恢复正常时发送通知", isOn: $model.config.notifications.on_recovery)
                            .toggleStyle(.switch)
                    }
                }

                Card(title: "macOS 本机通知", symbol: "macbook", tint: Brand.mint) {
                    Toggle("使用 macOS 系统通知中心弹出横幅提醒", isOn: $model.config.notifications.local_enabled)
                        .toggleStyle(.switch)
                }

                Card(title: "通用 Webhook", symbol: "link", tint: Brand.blue) {
                    VStack(alignment: .leading, spacing: 10) {
                        Toggle("启用 Webhook 推送", isOn: $model.config.notifications.webhook_enabled)
                            .toggleStyle(.switch)
                        if model.config.notifications.webhook_enabled {
                            TextField("https://example.com/ddns-hook", text: $model.config.notifications.webhook_url)
                                .textFieldStyle(.roundedBorder)
                            SecureField("可选 Bearer Token（存入钥匙串）", text: $model.notificationSecrets.webhookBearer)
                                .textFieldStyle(.roundedBorder)
                        }
                    }
                }

                Card(title: "Bark (iOS)", symbol: "bell.fill", tint: Brand.orange) {
                    VStack(alignment: .leading, spacing: 10) {
                        Toggle("启用 Bark 推送", isOn: $model.config.notifications.bark_enabled)
                            .toggleStyle(.switch)
                        if model.config.notifications.bark_enabled {
                            TextField("服务器地址（默认 https://api.day.app）", text: $model.config.notifications.bark_server)
                                .textFieldStyle(.roundedBorder)
                            SecureField("设备 Key（存入钥匙串）", text: $model.notificationSecrets.barkKey)
                                .textFieldStyle(.roundedBorder)
                        }
                    }
                }

                Card(title: "Gotify", symbol: "server.rack", tint: Brand.mint) {
                    VStack(alignment: .leading, spacing: 10) {
                        Toggle("启用 Gotify 推送", isOn: $model.config.notifications.gotify_enabled)
                            .toggleStyle(.switch)
                        if model.config.notifications.gotify_enabled {
                            TextField("https://gotify.example.com", text: $model.config.notifications.gotify_server)
                                .textFieldStyle(.roundedBorder)
                            SecureField("应用 Token（存入钥匙串）", text: $model.notificationSecrets.gotifyToken)
                                .textFieldStyle(.roundedBorder)
                        }
                    }
                }

                Card(title: "Telegram Bot", symbol: "paperplane.fill", tint: Brand.blue) {
                    VStack(alignment: .leading, spacing: 10) {
                        Toggle("启用 Telegram 机器人推送", isOn: $model.config.notifications.telegram_enabled)
                            .toggleStyle(.switch)
                        if model.config.notifications.telegram_enabled {
                            SecureField("Bot Token（存入钥匙串）", text: $model.notificationSecrets.telegramBotToken)
                                .textFieldStyle(.roundedBorder)
                            TextField("Chat ID", text: $model.config.notifications.telegram_chat_id)
                                .textFieldStyle(.roundedBorder)
                        }
                    }
                }

                HStack {
                    HStack(spacing: 6) {
                        Image(systemName: "lock.shield.fill")
                            .foregroundStyle(Brand.mint)
                        Text("Token、Key 等敏感凭据仅保存在 macOS 钥匙串中")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("发送测试通知", action: model.sendTestNotification)
                        .buttonStyle(.borderedProminent)
                        .tint(Brand.orange)
                }
                .padding(.top, 4)
            }
            .padding(Brand.pagePadding)
        }
    }
}


struct HistoryPage: View {
    @EnvironmentObject private var model: AppModel
    @State private var showClearAlert = false

    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                PageHeader(
                    title: "同步历史",
                    subtitle: "最近 100 次操作、公网地址与 DNS 记录变更轨迹",
                    symbol: "clock.arrow.circlepath",
                    tint: Brand.mint
                )
                Spacer()
                Button(role: .destructive) {
                    showClearAlert = true
                } label: {
                    Label("清空历史", systemImage: "trash")
                }
                .disabled(model.history.isEmpty)
                .confirmationDialog("确定要清空所有同步历史记录吗？", isPresented: $showClearAlert) {
                    Button("清空历史", role: .destructive) {
                        model.clearHistory()
                    }
                    Button("取消", role: .cancel) {}
                }
            }

            if model.history.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "clock.badge.checkmark")
                        .font(.system(size: 44))
                        .foregroundStyle(Brand.mint.opacity(0.6))
                    Text("暂无同步历史记录").font(.headline)
                    Text("完成 IP 检测、演练或 DNS 同步后，操作记录将在此展示")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(model.history) { entry in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 8) {
                            HStack(spacing: 4) {
                                Image(systemName: entry.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                Text("\(entry.action)\(entry.success ? "成功" : "失败")")
                                    .font(.system(.subheadline, weight: .semibold))
                            }
                            .foregroundStyle(entry.success ? Brand.mint : Brand.rose)

                            Spacer()

                            Text(Self.formatter.string(from: entry.date))
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)

                            Text(String(format: "%.1f 秒", entry.duration))
                                .font(.caption.monospacedDigit())
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Capsule().fill(Color.primary.opacity(0.06)))
                                .foregroundStyle(.secondary)
                        }

                        HStack(spacing: 12) {
                            if !entry.ipv4.isEmpty {
                                HStack(spacing: 4) {
                                    Text("IPv4:").font(.caption2).foregroundStyle(.secondary)
                                    Text(entry.ipv4).font(.caption.monospaced())
                                }
                            }
                            if !entry.ipv6.isEmpty {
                                HStack(spacing: 4) {
                                    Text("IPv6:").font(.caption2).foregroundStyle(.secondary)
                                    Text(entry.ipv6).font(.caption.monospaced())
                                }
                            }
                            if !entry.summary.isEmpty {
                                Text("· \(entry.summary)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }

                        if !entry.changes.isEmpty {
                            VStack(alignment: .leading, spacing: 3) {
                                ForEach(entry.changes, id: \.self) { change in
                                    HStack(spacing: 6) {
                                        Circle().fill(Brand.blue).frame(width: 4, height: 4)
                                        Text(change)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                            .padding(.top, 2)
                        }
                    }
                    .padding(12)
                    .background(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(Brand.surface)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .strokeBorder(Color.primary.opacity(0.05), lineWidth: 1)
                    )
                    .padding(.vertical, 2)
                }
                .listStyle(.inset)
            }
        }
        .padding(Brand.pagePadding)
    }
}


struct LogPage: View {
    @EnvironmentObject private var model: AppModel
    @State private var selectedFilter: LogFilter = .all
    @State private var searchText = ""
    @State private var justCopied = false

    private var filteredEntries: [LogEntry] {
        model.logEntries.filter { entry in
            let levelMatches = selectedFilter.level.map { $0 == entry.level } ?? true
            let textMatches = searchText.isEmpty
                || entry.text.localizedCaseInsensitiveContains(searchText)
            return levelMatches && textMatches
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                PageHeader(
                    title: "运行日志",
                    subtitle: "后台探测与同步任务的实时输出",
                    symbol: "text.alignleft",
                    tint: Brand.blue
                )
                Spacer()
                Button {
                    model.copyLog()
                    justCopied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) {
                        justCopied = false
                    }
                } label: {
                    Label(justCopied ? "已复制" : "复制", systemImage: justCopied ? "checkmark" : "doc.on.doc")
                }
                .disabled(model.logEntries.isEmpty)

                Button(role: .destructive, action: model.clearLog) {
                    Label("清空", systemImage: "trash")
                }
                .disabled(model.logEntries.isEmpty)
            }

            HStack(spacing: 10) {
                Picker("日志分类", selection: $selectedFilter) {
                    ForEach(LogFilter.allCases) { filter in
                        Text("\(filter.title)（\(count(for: filter))）").tag(filter)
                    }
                }
                .pickerStyle(.segmented)

                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                        .font(.caption)
                    TextField("筛选关键词", text: $searchText)
                        .textFieldStyle(.plain)
                    if !searchText.isEmpty {
                        Button {
                            searchText = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                                .font(.caption)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Brand.surface)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(Color.primary.opacity(0.1), lineWidth: 1)
                )
                .frame(minWidth: 160, idealWidth: 200, maxWidth: 260)

                if selectedFilter != .all || !searchText.isEmpty {
                    Button("重置") {
                        selectedFilter = .all
                        searchText = ""
                    }
                    .buttonStyle(.borderless)
                    .font(.caption)
                }
            }

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        if filteredEntries.isEmpty {
                            Text(model.logEntries.isEmpty ? "暂无日志输出" : "没有符合筛选条件的日志")
                                .foregroundStyle(.secondary)
                                .font(.callout)
                                .padding(.vertical, 30)
                                .frame(maxWidth: .infinity)
                        }
                        ForEach(filteredEntries) { entry in
                            HStack(alignment: .top, spacing: 8) {
                                Text(entry.timestamp)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .frame(width: 58, alignment: .leading)

                                Image(systemName: entry.level.symbol)
                                    .font(.caption2)
                                    .foregroundStyle(entry.level.color)
                                    .frame(width: 14)

                                Text(entry.text)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(
                                        entry.level == .error || entry.level == .warning
                                            ? entry.level.color
                                            : Color.primary
                                    )
                                    .textSelection(.enabled)
                                    .fixedSize(horizontal: false, vertical: true)

                                Spacer(minLength: 0)
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 3)
                            .id(entry.id)
                        }
                    }
                    .padding(.vertical, 10)
                }
                .background(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(Color(nsColor: .textBackgroundColor))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .strokeBorder(Color.primary.opacity(0.08), lineWidth: 1)
                )
                .onChange(of: model.logEntries.count) { _ in
                    if let last = model.logEntries.last {
                        withAnimation(.easeOut(duration: 0.15)) {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }
        }
        .padding(Brand.pagePadding)
    }

    private func count(for filter: LogFilter) -> Int {
        guard let level = filter.level else { return model.logEntries.count }
        return model.logEntries.lazy.filter { $0.level == level }.count
    }
}


// MARK: - Shell

enum SidebarSection: String, CaseIterable, Identifiable {
    case overview, cloudflare, records, network, notifications, history, log

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: return "概览"
        case .cloudflare: return "Cloudflare"
        case .records: return "DNS 记录"
        case .network: return "网络与调度"
        case .notifications: return "通知推送"
        case .history: return "同步历史"
        case .log: return "运行日志"
        }
    }

    var symbol: String {
        switch self {
        case .overview: return "square.grid.2x2.fill"
        case .cloudflare: return "cloud.fill"
        case .records: return "list.bullet.rectangle.portrait.fill"
        case .network: return "antenna.radiowaves.left.and.right"
        case .notifications: return "bell.badge.fill"
        case .history: return "clock.arrow.circlepath"
        case .log: return "text.alignleft"
        }
    }

    var tint: Color {
        switch self {
        case .overview: return Brand.blue
        case .cloudflare: return Brand.orange
        case .records: return Brand.mint
        case .network: return Brand.blue
        case .notifications: return Brand.amber
        case .history: return Brand.mint
        case .log: return Brand.purple
        }
    }
}


struct OnboardingView: View {
    @EnvironmentObject private var model: AppModel
    @State private var step = 0
    @State private var revealToken = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(nsImage: NSApplication.shared.applicationIconImage)
                    .resizable()
                    .frame(width: 44, height: 44)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                    .shadow(color: .black.opacity(0.15), radius: 4, y: 2)

                VStack(alignment: .leading, spacing: 2) {
                    Text("初始化配置 Cloudflare DDNS").font(.title2.bold())
                    Text("第 \(step + 1) 步，共 3 步 · 轻松完成动态域名解析设置")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("稍后设置") { model.showOnboarding = false }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
            }
            .padding(Brand.pagePadding)
            .background(Brand.surface)

            Divider()

            Group {
                switch step {
                case 0: tokenStep
                case 1: zoneStep
                default: recordStep
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .padding(24)

            Divider()

            HStack {
                if step > 0 {
                    Button("上一步") { step -= 1 }
                }
                Spacer()
                Text(model.statusText).font(.caption).foregroundStyle(.secondary)
                if step < 2 {
                    Button("下一步") { step += 1 }
                        .buttonStyle(.borderedProminent)
                        .tint(Brand.blue)
                        .disabled(step == 0 ? !model.hasToken : model.config.cloudflare.zone_id == nil)
                } else {
                    Button("保存并完成") { model.finishOnboarding() }
                        .buttonStyle(.borderedProminent)
                        .tint(Brand.mint)
                        .disabled(model.config.records.isEmpty || model.isRunning)
                }
            }
            .padding(18)
            .background(Brand.surface)
        }
        .frame(width: 720, height: 560)
    }

    private var tokenStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("第一步：填写 API Token", systemImage: "key.fill")
                .font(.title3.bold())
                .foregroundStyle(Brand.orange)

            Text("在 Cloudflare 控制台创建 Token，需包含 Zone:Read 与 DNS:Edit 权限。Token 将安全存入 macOS 钥匙串。")
                .foregroundStyle(.secondary)

            HStack(spacing: 8) {
                Group {
                    if revealToken {
                        TextField("Cloudflare API Token", text: $model.token)
                    } else {
                        SecureField("Cloudflare API Token", text: $model.token)
                    }
                }
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))

                Button { revealToken.toggle() } label: {
                    Image(systemName: revealToken ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
            }

            Button("验证 Token 并发现区域") { model.discoverCloudflare() }
                .buttonStyle(.borderedProminent)
                .tint(Brand.orange)
                .disabled(!model.hasToken || model.isRunning)

            if !model.discoveredZones.isEmpty {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(Brand.mint)
                    Text("验证成功！已发现 \(model.discoveredZones.count) 个区域")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(Brand.mint)
                }
                .padding(8)
                .background(RoundedRectangle(cornerRadius: 8).fill(Brand.mint.opacity(0.12)))
            }
        }
    }

    private var zoneStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("第二步：选择托管区域", systemImage: "globe.asia.australia.fill")
                .font(.title3.bold())
                .foregroundStyle(Brand.blue)

            if model.discoveredZones.isEmpty {
                Text("尚未发现区域，请返回上一步验证 Token。")
                    .foregroundStyle(.secondary)
            } else {
                List(model.discoveredZones) { zone in
                    Button {
                        model.selectDiscoveredZone(zone)
                    } label: {
                        HStack {
                            Image(systemName: model.config.cloudflare.zone_id == zone.id
                                  ? "checkmark.circle.fill" : "circle")
                                .foregroundStyle(model.config.cloudflare.zone_id == zone.id ? Brand.blue : .secondary)
                            Text(zone.name).font(.body.weight(.medium))
                            Spacer()
                            Text(zone.status ?? "").font(.caption).foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 4)
                    }
                    .buttonStyle(.plain)
                }
                .frame(height: 320)
                .background(
                    RoundedRectangle(cornerRadius: 10)
                        .fill(Brand.surface)
                )
            }
        }
    }

    private var recordStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("第三步：选择要同步的域名记录", systemImage: "list.bullet.rectangle")
                .font(.title3.bold())
                .foregroundStyle(Brand.mint)

            Text("导入 Cloudflare 中已存在的 A/AAAA 记录，或在此快速添加。")
                .foregroundStyle(.secondary)

            if model.discoveredRecords.isEmpty {
                VStack(spacing: 10) {
                    Text(model.isRunning ? "正在从 Cloudflare 读取记录…" : "该区域暂未查询到已有记录，可先添加默认主机名")
                        .foregroundStyle(.secondary)
                    Button("添加 home.\(model.config.cloudflare.zone_name)") {
                        model.addRecord()
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding(.vertical, 20)
            } else {
                List(model.discoveredRecords) { record in
                    HStack {
                        Text(record.type)
                            .font(.caption.bold())
                            .frame(width: 44)
                            .foregroundStyle(record.type == "A" ? Brand.blue : Brand.mint)
                        Text(record.name)
                            .font(.system(.body, design: .monospaced))
                        Spacer()
                        Button(model.isRecordImported(record) ? "已添加" : "添加为同步") {
                            model.importDiscoveredRecord(record)
                        }
                        .disabled(model.isRecordImported(record))
                    }
                    .padding(.vertical, 2)
                }
                .frame(height: 280)
            }

            Text("已配置 \(model.config.records.count) 条同步记录")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
        }
    }
}


struct ContentView: View {
    @EnvironmentObject private var model: AppModel
    @State private var selection: SidebarSection? = .overview

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            detail
                .frame(minWidth: 640)
                .background(Brand.windowBackground)
                .toolbar { toolbarContent }
        }
        .tint(Brand.blue)
        .frame(minWidth: 1040, minHeight: 700)
        .sheet(isPresented: $model.showOnboarding) {
            OnboardingView().environmentObject(model)
        }
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(nsImage: NSApplication.shared.applicationIconImage)
                    .resizable()
                    .frame(width: 36, height: 36)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .strokeBorder(Color.white.opacity(0.2), lineWidth: 0.8)
                    )
                    .shadow(color: .black.opacity(0.12), radius: 3, y: 1)

                VStack(alignment: .leading, spacing: 1) {
                    Text(applicationName)
                        .font(.system(.headline, weight: .bold))
                    Text("直连 · 智能多活同步")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 16)

            List(selection: $selection) {
                Section("管理面板") {
                    ForEach(SidebarSection.allCases) { section in
                        NavigationLink(value: section) {
                            HStack(spacing: 10) {
                                Image(systemName: section.symbol)
                                    .font(.system(size: 14, weight: .medium))
                                    .foregroundStyle(selection == section ? Brand.blue : Color.secondary)
                                    .frame(width: 20)

                                Text(section.title)
                                    .font(.system(.body, weight: selection == section ? .semibold : .regular))

                                Spacer()

                                if section == .records && !model.config.records.isEmpty {
                                    Text("\(model.config.records.count)")
                                        .font(.caption2.weight(.bold))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 1)
                                        .background(Capsule().fill(Color.primary.opacity(0.08)))
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
            }
            .listStyle(.sidebar)
            .scrollContentBackground(.hidden)

            Divider()

            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    StatusPill(state: model.runState, text: model.statusText)
                    Spacer()
                    if model.schedulerEnabled {
                        HStack(spacing: 4) {
                            Image(systemName: "timer")
                                .font(.caption2)
                            Text(model.schedulerDescription)
                                .font(.caption2.monospacedDigit())
                        }
                        .foregroundStyle(.secondary)
                    }
                }

                Button {
                    model.saveButtonPressed()
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "tray.and.arrow.down.fill")
                        Text("保存配置")
                            .font(.body.weight(.medium))
                    }
                    .frame(maxWidth: .infinity)
                }
                .controlSize(.regular)
                .buttonStyle(.borderedProminent)
                .tint(Brand.blue)
                .disabled(model.isRunning)
            }
            .padding(14)
            .padding(.top, 2)
            .background(Brand.surface.opacity(0.72))
        }
        .frame(minWidth: 224, idealWidth: 248, maxWidth: 286)
    }

    @ViewBuilder
    private var detail: some View {
        switch selection ?? .overview {
        case .overview: OverviewPage(selection: $selection)
        case .cloudflare: CloudflarePage()
        case .records: RecordsPage()
        case .network: NetworkPage()
        case .notifications: NotificationsPage()
        case .history: HistoryPage()
        case .log: LogPage()
        }
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            StatusPill(state: model.runState, text: model.statusText)
        }
        ToolbarItemGroup(placement: .primaryAction) {
            if model.isRunning {
                Button(role: .destructive, action: model.cancelRun) {
                    Label("停止", systemImage: "stop.circle.fill")
                }
                .help("终止当前运行中的后台任务")
            }

            Button(action: model.checkIP) {
                Label("检测 IP", systemImage: "dot.radiowaves.left.and.right")
            }
            .disabled(model.isRunning)
            .help("仅探测本地公网 IPv4/IPv6，不调用 Cloudflare API")

            Button(action: model.dryRun) {
                Label("演练", systemImage: "wand.and.stars")
            }
            .disabled(model.isRunning)
            .help("模拟同步全流程并展示预估变更，不修改任何线上 DNS 记录")

            Button(action: model.syncNow) {
                Label("立即同步", systemImage: "arrow.triangle.2.circlepath")
            }
            .disabled(model.isRunning)
            .help("立即执行公网 IP 探测与 Cloudflare DNS 记录同步")
        }
    }
}


struct MenuBarContentView: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Label(
            "\(model.statusText) · \(model.schedulerDescription)",
            systemImage: statusSymbol
        )

        if !model.detectedIPv4.isEmpty {
            Label("IPv4：\(model.detectedIPv4)", systemImage: "4.circle.fill")
        }
        if !model.detectedIPv6.isEmpty {
            Label("IPv6：\(model.detectedIPv6)", systemImage: "6.circle.fill")
        }

        Divider()

        Button {
            model.syncNow()
        } label: {
            Label("立即同步", systemImage: "arrow.triangle.2.circlepath")
        }
        .disabled(model.isRunning)

        Button {
            model.checkIP()
        } label: {
            Label("检测公网 IP", systemImage: "dot.radiowaves.left.and.right")
        }
        .disabled(model.isRunning)

        Button {
            model.setScheduler(!model.schedulerEnabled)
        } label: {
            Label(
                model.schedulerEnabled ? "停止定时同步" : "开启定时同步",
                systemImage: model.schedulerEnabled ? "pause.circle" : "clock.arrow.circlepath"
            )
        }

        Divider()

        Button {
            showMainWindow()
        } label: {
            Label("打开主窗口", systemImage: "macwindow")
        }

        Button {
            model.checkForUpdates()
        } label: {
            Label("检查更新", systemImage: "arrow.down.circle")
        }

        Button {
            NSApplication.shared.terminate(nil)
        } label: {
            Label("退出应用", systemImage: "power")
        }
    }

    private var statusSymbol: String {
        switch model.runState {
        case .running: return "arrow.triangle.2.circlepath"
        case .failure: return "exclamationmark.triangle.fill"
        case .success: return "checkmark.circle.fill"
        case .idle: return "cloud.fill"
        }
    }

    private func showMainWindow() {
        openWindow(id: mainWindowSceneID)
        DispatchQueue.main.async {
            NSApplication.shared.activate(ignoringOtherApps: true)
        }
    }
}


/// The menu bar label remains alive even after the last main window is closed,
/// so it can service a Dock reopen request by creating the SwiftUI Window scene.
private struct MenuBarLabel: View {
    let symbol: String
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(systemName: symbol)
            .accessibilityLabel(applicationName)
            .onReceive(
                NotificationCenter.default.publisher(for: .openMainWindowRequested)
            ) { _ in
                openWindow(id: mainWindowSceneID)
                DispatchQueue.main.async {
                    NSApplication.shared.activate(ignoringOtherApps: true)
                }
            }
    }
}


@main
struct DirectCloudflareDDNSApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        Window(applicationName, id: mainWindowSceneID) {
            ContentView()
                .environmentObject(model)
        }
        .windowStyle(.titleBar)
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("检测公网 IP") { model.checkIP() }
                    .keyboardShortcut("i", modifiers: [.command, .shift])
                Button("立即同步") { model.syncNow() }
                    .keyboardShortcut("s", modifiers: [.command, .shift])
                Button("保存配置") { model.saveButtonPressed() }
                    .keyboardShortcut("s", modifiers: [.command])
            }
        }

        MenuBarExtra {
            MenuBarContentView(model: model)
        } label: {
            MenuBarLabel(symbol: menuBarSymbol)
        }
        .menuBarExtraStyle(.menu)
    }

    private var menuBarSymbol: String {
        switch model.runState {
        case .running: return "arrow.triangle.2.circlepath"
        case .failure: return "exclamationmark.icloud"
        default: return model.schedulerEnabled ? "cloud.fill" : "cloud"
        }
    }
}
