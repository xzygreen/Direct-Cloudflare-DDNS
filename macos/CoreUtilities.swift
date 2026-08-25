import Foundation
import Darwin

enum AppFailure: LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self {
        case .message(let text): return text
        }
    }
}


enum AddressParser {
    static func isIPv4(_ text: String) -> Bool {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { part in
            guard !part.isEmpty, part.count <= 3,
                  part.allSatisfy({ $0.isNumber }),
                  let value = Int(part), (0...255).contains(value) else { return false }
            return true
        }
    }

    static func isIPv6(_ text: String) -> Bool {
        guard text.contains(":"), text.count >= 3, text.count <= 45 else { return false }
        var address = in6_addr()
        return text.withCString { inet_pton(AF_INET6, $0, &address) == 1 }
    }

    static func addresses(in line: String) -> (v4: String?, v6: String?) {
        // Keep the ASCII colon because it is part of an IPv6 address.  The
        // backend's localized output uses a full-width colon after labels and
        // a full-width semicolon between address families.
        let separators = CharacterSet(charactersIn: " \t：，,；;（）()<>[]\"'>-")
        var v4: String?
        var v6: String?
        for rawToken in line.components(separatedBy: separators) where !rawToken.isEmpty {
            let token: String
            if rawToken.lowercased().hasPrefix("ipv4:")
                || rawToken.lowercased().hasPrefix("ipv6:") {
                token = String(rawToken.dropFirst(5))
            } else {
                token = rawToken
            }
            if isIPv4(token) {
                v4 = token
            } else if isIPv6(token) {
                v6 = token
            }
        }
        return (v4, v6)
    }
}


enum DomainValidator {
    static func normalized(_ value: String, allowWildcard: Bool) throws -> String {
        var name = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty, name.count <= 253 else {
            throw AppFailure.message("域名为空或长度超过 253 个字符")
        }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        let permitted = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
        for (index, rawLabel) in labels.enumerated() {
            let label = String(rawLabel)
            guard !label.isEmpty, label.count <= 63 else {
                throw AppFailure.message("域名包含空标签或超过 63 个字符的标签：\(name)")
            }
            if label == "*" {
                guard allowWildcard, index == 0 else {
                    throw AppFailure.message("通配符 * 只能位于记录域名最左侧")
                }
                continue
            }
            guard !label.hasPrefix("-"), !label.hasSuffix("-") else {
                throw AppFailure.message("域名标签不能以连字符开头或结尾：\(label)")
            }
            guard label.unicodeScalars.allSatisfy({ permitted.contains($0) }) else {
                throw AppFailure.message("域名包含空格或非法字符：\(label)")
            }
        }
        return name
    }
}
