#include "certpin/certpin.hpp"

#include <cassert>
#include <vector>

int main() {
    const std::vector<std::uint8_t> spki = {'s', 'p', 'k', 'i'};
    const std::string fp = certpin::SpkiFingerprintBase64(spki);

    const std::string record = "v=CERTPIN1; fp=" + fp + "; exp=2026-12-31; ttl=3600";
    const certpin::Policy policy = certpin::ParseRecord(record);

    assert(policy.version == "CERTPIN1");
    assert(policy.fingerprints.size() == 1);
    assert(policy.ttl_seconds.has_value() && policy.ttl_seconds.value() == 3600);

    const certpin::Decision match =
        certpin::Evaluate(std::optional<std::string>(record), spki, certpin::Date{2026, 4, 21});
    assert(match == certpin::Decision::kMatch);

    const certpin::Decision no_policy_expired = certpin::Evaluate(
        std::optional<std::string>("v=CERTPIN1; fp=" + fp + "; exp=2020-01-01"),
        spki,
        certpin::Date{2026, 4, 21});
    assert(no_policy_expired == certpin::Decision::kNoPolicy);

    const certpin::Decision malformed = certpin::Evaluate(
        std::optional<std::string>("v=CERTPIN1"),
        spki,
        certpin::Date{2026, 4, 21});
    assert(malformed == certpin::Decision::kMalformed);

    return 0;
}
