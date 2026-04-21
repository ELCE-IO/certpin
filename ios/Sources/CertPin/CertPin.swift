import Foundation
import CryptoKit

public struct CertPinPolicy: Equatable {
    public let version: String
    public let fingerprints: [String]
    public let expirationDate: Date?
    public let ttlHintSeconds: UInt32?
}

public enum CertPinDecision: Equatable {
    case noPolicy
    case match
    case mismatch
    case malformed
}

public enum CertPinError: Error, Equatable, CustomStringConvertible {
    case emptyRecord
    case malformedTag(String)
    case unknownTag(String)
    case duplicateTag(String)
    case invalidVersion(String)
    case missingVersion
    case missingFingerprint
    case invalidFingerprint(String)
    case invalidExpiration(String)
    case invalidTTL(String)

    public var description: String {
        switch self {
        case .emptyRecord:
            return "Record is empty."
        case .malformedTag(let raw):
            return "Malformed tag: \(raw)"
        case .unknownTag(let key):
            return "Unknown tag: \(key)"
        case .duplicateTag(let key):
            return "Duplicate tag: \(key)"
        case .invalidVersion(let value):
            return "Invalid version value: \(value)"
        case .missingVersion:
            return "Missing required tag: v"
        case .missingFingerprint:
            return "Missing required tag: fp"
        case .invalidFingerprint(let value):
            return "Invalid fingerprint: \(value)"
        case .invalidExpiration(let value):
            return "Invalid expiration date: \(value)"
        case .invalidTTL(let value):
            return "Invalid ttl value: \(value)"
        }
    }
}

public enum CertPin {
    public static let expectedVersion = "CERTPIN1"

    private static let utcCalendar: Calendar = {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? TimeZone(identifier: "UTC") ?? TimeZone.current
        return calendar
    }()

    private static let expFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.isLenient = false
        return formatter
    }()

    public static func parse(record: String) throws -> CertPinPolicy {
        let normalized = normalizeRecord(record)
        guard !normalized.isEmpty else {
            throw CertPinError.emptyRecord
        }

        var version: String?
        var fingerprints: [String] = []
        var expirationDate: Date?
        var ttlHintSeconds: UInt32?

        for rawPart in normalized.split(separator: ";", omittingEmptySubsequences: false) {
            let part = rawPart.trimmingCharacters(in: .whitespacesAndNewlines)
            if part.isEmpty {
                continue
            }

            guard let separatorIndex = part.firstIndex(of: "=") else {
                throw CertPinError.malformedTag(part)
            }

            let key = part[..<separatorIndex].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = part[part.index(after: separatorIndex)...]
                .trimmingCharacters(in: .whitespacesAndNewlines)

            switch key {
            case "v":
                if version != nil {
                    throw CertPinError.duplicateTag("v")
                }
                guard value == expectedVersion else {
                    throw CertPinError.invalidVersion(value)
                }
                version = value

            case "fp":
                guard let decoded = Data(base64Encoded: value), decoded.count == 32 else {
                    throw CertPinError.invalidFingerprint(value)
                }
                fingerprints.append(decoded.base64EncodedString())

            case "exp":
                if expirationDate != nil {
                    throw CertPinError.duplicateTag("exp")
                }
                guard let date = expFormatter.date(from: value) else {
                    throw CertPinError.invalidExpiration(value)
                }
                expirationDate = date

            case "ttl":
                if ttlHintSeconds != nil {
                    throw CertPinError.duplicateTag("ttl")
                }
                guard let ttl = UInt32(value), ttl > 0 else {
                    throw CertPinError.invalidTTL(value)
                }
                ttlHintSeconds = ttl

            default:
                throw CertPinError.unknownTag(key)
            }
        }

        guard let parsedVersion = version else {
            throw CertPinError.missingVersion
        }
        guard !fingerprints.isEmpty else {
            throw CertPinError.missingFingerprint
        }

        return CertPinPolicy(
            version: parsedVersion,
            fingerprints: fingerprints,
            expirationDate: expirationDate,
            ttlHintSeconds: ttlHintSeconds
        )
    }

    public static func spkiFingerprintBase64(spkiDer: Data) -> String {
        let digest = SHA256.hash(data: spkiDer)
        return Data(digest).base64EncodedString()
    }

    public static func evaluate(record: String?, spkiDer: Data, now: Date = Date()) -> CertPinDecision {
        guard let record = record, !normalizeRecord(record).isEmpty else {
            return .noPolicy
        }

        let policy: CertPinPolicy
        do {
            policy = try parse(record: record)
        } catch {
            return .malformed
        }

        if isExpired(policy: policy, now: now) {
            return .noPolicy
        }

        let fingerprint = spkiFingerprintBase64(spkiDer: spkiDer)
        return policy.fingerprints.contains(fingerprint) ? .match : .mismatch
    }

    public static func isExpired(policy: CertPinPolicy, now: Date = Date()) -> Bool {
        guard let exp = policy.expirationDate else {
            return false
        }
        let todayUTC = utcCalendar.startOfDay(for: now)
        let expUTC = utcCalendar.startOfDay(for: exp)
        return todayUTC > expUTC
    }

    private static func normalizeRecord(_ record: String) -> String {
        let trimmed = record.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("\""), trimmed.hasSuffix("\""), trimmed.count >= 2 {
            return String(trimmed.dropFirst().dropLast()).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return trimmed
    }
}
