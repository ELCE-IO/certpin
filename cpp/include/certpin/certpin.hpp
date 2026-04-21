#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace certpin {

inline constexpr const char* kExpectedVersion = "CERTPIN1";

struct Date {
    int year = 0;
    int month = 0;
    int day = 0;
};

bool operator==(const Date& lhs, const Date& rhs);
bool operator>(const Date& lhs, const Date& rhs);

struct Policy {
    std::string version;
    std::vector<std::string> fingerprints;
    std::optional<Date> exp;
    std::optional<std::uint32_t> ttl_seconds;

    bool IsExpired(const Date& today_utc) const;
};

enum class Decision {
    kNoPolicy,
    kMatch,
    kMismatch,
    kMalformed,
};

class ParseException : public std::runtime_error {
public:
    explicit ParseException(const std::string& message);
};

Policy ParseRecord(const std::string& record);
std::string SpkiFingerprintBase64(const std::vector<std::uint8_t>& spki_der);
Decision Evaluate(const std::optional<std::string>& record,
                  const std::vector<std::uint8_t>& spki_der,
                  const Date& today_utc);
Date UtcToday();

}  // namespace certpin
