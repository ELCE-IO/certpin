#include "certpin/certpin.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <ctime>
#include <limits>
#include <sstream>
#include <tuple>

#include <openssl/evp.h>
#include <openssl/sha.h>

namespace certpin {

namespace {

std::string Trim(const std::string& value) {
    std::size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }

    std::size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }

    return value.substr(start, end - start);
}

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string NormalizeRecord(const std::string& record) {
    std::string trimmed = Trim(record);
    if (trimmed.size() >= 2 && trimmed.front() == '"' && trimmed.back() == '"') {
        return Trim(trimmed.substr(1, trimmed.size() - 2));
    }
    return trimmed;
}

bool IsLeapYear(int year) {
    if (year % 400 == 0) {
        return true;
    }
    if (year % 100 == 0) {
        return false;
    }
    return year % 4 == 0;
}

int DaysInMonth(int year, int month) {
    static const std::array<int, 12> kDays = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month < 1 || month > 12) {
        return 0;
    }
    if (month == 2 && IsLeapYear(year)) {
        return 29;
    }
    return kDays[static_cast<std::size_t>(month - 1)];
}

Date ParseDate(const std::string& value) {
    if (value.size() != 10 || value[4] != '-' || value[7] != '-') {
        throw ParseException("Invalid exp date: " + value);
    }
    for (std::size_t idx : {0U, 1U, 2U, 3U, 5U, 6U, 8U, 9U}) {
        if (!std::isdigit(static_cast<unsigned char>(value[idx]))) {
            throw ParseException("Invalid exp date: " + value);
        }
    }

    Date date;
    date.year = std::stoi(value.substr(0, 4));
    date.month = std::stoi(value.substr(5, 2));
    date.day = std::stoi(value.substr(8, 2));

    const int max_day = DaysInMonth(date.year, date.month);
    if (max_day == 0 || date.day < 1 || date.day > max_day) {
        throw ParseException("Invalid exp date: " + value);
    }
    return date;
}

bool IsBase64CoreChar(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
}

std::vector<std::uint8_t> DecodeBase64Strict(const std::string& value) {
    if (value.empty() || value.size() % 4 != 0) {
        throw ParseException("Invalid fp base64: " + value);
    }

    std::size_t padding = 0;
    if (!value.empty() && value.back() == '=') {
        padding += 1;
        if (value.size() >= 2 && value[value.size() - 2] == '=') {
            padding += 1;
        }
    }

    for (std::size_t i = 0; i < value.size() - padding; ++i) {
        if (!IsBase64CoreChar(value[i])) {
            throw ParseException("Invalid fp base64: " + value);
        }
    }
    for (std::size_t i = value.size() - padding; i < value.size(); ++i) {
        if (value[i] != '=') {
            throw ParseException("Invalid fp base64: " + value);
        }
    }

    std::vector<std::uint8_t> decoded((value.size() / 4) * 3);
    int out_len =
        EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char*>(value.data()), static_cast<int>(value.size()));
    if (out_len < 0) {
        throw ParseException("Invalid fp base64: " + value);
    }

    out_len -= static_cast<int>(padding);
    decoded.resize(static_cast<std::size_t>(out_len));
    return decoded;
}

std::string EncodeBase64(const std::vector<std::uint8_t>& bytes) {
    if (bytes.empty()) {
        return "";
    }
    const int out_len = 4 * ((static_cast<int>(bytes.size()) + 2) / 3);
    std::string encoded(static_cast<std::size_t>(out_len), '\0');
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&encoded[0]), bytes.data(), static_cast<int>(bytes.size()));
    return encoded;
}

}  // namespace

bool operator==(const Date& lhs, const Date& rhs) {
    return std::tie(lhs.year, lhs.month, lhs.day) == std::tie(rhs.year, rhs.month, rhs.day);
}

bool operator>(const Date& lhs, const Date& rhs) {
    return std::tie(lhs.year, lhs.month, lhs.day) > std::tie(rhs.year, rhs.month, rhs.day);
}

bool Policy::IsExpired(const Date& today_utc) const {
    if (!exp.has_value()) {
        return false;
    }
    return today_utc > exp.value();
}

ParseException::ParseException(const std::string& message) : std::runtime_error(message) {}

Policy ParseRecord(const std::string& record) {
    const std::string normalized = NormalizeRecord(record);
    if (normalized.empty()) {
        throw ParseException("Record is empty.");
    }

    std::optional<std::string> version;
    std::vector<std::string> fingerprints;
    std::optional<Date> exp;
    std::optional<std::uint32_t> ttl_seconds;

    std::stringstream stream(normalized);
    std::string raw_part;
    while (std::getline(stream, raw_part, ';')) {
        const std::string part = Trim(raw_part);
        if (part.empty()) {
            continue;
        }

        const auto sep = part.find('=');
        if (sep == std::string::npos || sep == 0 || sep == part.size() - 1) {
            throw ParseException("Malformed tag: " + part);
        }

        const std::string key = ToLower(Trim(part.substr(0, sep)));
        const std::string value = Trim(part.substr(sep + 1));
        if (value.empty()) {
            throw ParseException("Malformed tag: " + part);
        }

        if (key == "v") {
            if (version.has_value()) {
                throw ParseException("Duplicate tag: v");
            }
            if (value != kExpectedVersion) {
                throw ParseException("Invalid version: " + value);
            }
            version = value;
            continue;
        }

        if (key == "fp") {
            std::vector<std::uint8_t> decoded = DecodeBase64Strict(value);
            if (decoded.size() != 32) {
                throw ParseException("Invalid fp length (expected SHA-256 bytes): " + value);
            }
            fingerprints.push_back(EncodeBase64(decoded));
            continue;
        }

        if (key == "exp") {
            if (exp.has_value()) {
                throw ParseException("Duplicate tag: exp");
            }
            exp = ParseDate(value);
            continue;
        }

        if (key == "ttl") {
            if (ttl_seconds.has_value()) {
                throw ParseException("Duplicate tag: ttl");
            }
            std::uint64_t parsed = 0;
            try {
                parsed = static_cast<std::uint64_t>(std::stoull(value));
            } catch (...) {
                throw ParseException("Invalid ttl: " + value);
            }
            if (parsed == 0 || parsed > std::numeric_limits<std::uint32_t>::max()) {
                throw ParseException("Invalid ttl: " + value);
            }
            ttl_seconds = static_cast<std::uint32_t>(parsed);
            continue;
        }

        throw ParseException("Unknown tag: " + key);
    }

    if (!version.has_value()) {
        throw ParseException("Missing required tag: v");
    }
    if (fingerprints.empty()) {
        throw ParseException("Missing required tag: fp");
    }

    Policy policy;
    policy.version = *version;
    policy.fingerprints = std::move(fingerprints);
    policy.exp = exp;
    policy.ttl_seconds = ttl_seconds;
    return policy;
}

std::string SpkiFingerprintBase64(const std::vector<std::uint8_t>& spki_der) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    SHA256(spki_der.data(), spki_der.size(), digest.data());
    std::vector<std::uint8_t> digest_vec(digest.begin(), digest.end());
    return EncodeBase64(digest_vec);
}

Decision Evaluate(const std::optional<std::string>& record,
                  const std::vector<std::uint8_t>& spki_der,
                  const Date& today_utc) {
    if (!record.has_value() || NormalizeRecord(*record).empty()) {
        return Decision::kNoPolicy;
    }

    Policy policy;
    try {
        policy = ParseRecord(*record);
    } catch (const ParseException&) {
        return Decision::kMalformed;
    }

    if (policy.IsExpired(today_utc)) {
        return Decision::kNoPolicy;
    }

    const std::string fingerprint = SpkiFingerprintBase64(spki_der);
    const auto it = std::find(policy.fingerprints.begin(), policy.fingerprints.end(), fingerprint);
    if (it != policy.fingerprints.end()) {
        return Decision::kMatch;
    }
    return Decision::kMismatch;
}

Date UtcToday() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t now_time = std::chrono::system_clock::to_time_t(now);

    std::tm utc_tm {};
#if defined(_WIN32)
    gmtime_s(&utc_tm, &now_time);
#else
    gmtime_r(&now_time, &utc_tm);
#endif

    Date date;
    date.year = utc_tm.tm_year + 1900;
    date.month = utc_tm.tm_mon + 1;
    date.day = utc_tm.tm_mday;
    return date;
}

}  // namespace certpin
