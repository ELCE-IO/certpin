import XCTest
@testable import CertPin

final class CertPinTests: XCTestCase {
    func testParseValidRecord() throws {
        let spki = Data("spki".utf8)
        let fp = CertPin.spkiFingerprintBase64(spkiDer: spki)
        let record = "v=CERTPIN1; fp=\(fp); exp=2026-12-31; ttl=3600"

        let parsed = try CertPin.parse(record: record)

        XCTAssertEqual(parsed.version, "CERTPIN1")
        XCTAssertEqual(parsed.fingerprints, [fp])
        XCTAssertEqual(parsed.ttlHintSeconds, 3600)
        XCTAssertNotNil(parsed.expirationDate)
    }

    func testMalformedRecordUnknownTag() {
        let fp = CertPin.spkiFingerprintBase64(spkiDer: Data("spki".utf8))
        XCTAssertThrowsError(try CertPin.parse(record: "v=CERTPIN1; fp=\(fp); x=1")) { error in
            guard case CertPinError.unknownTag = error else {
                return XCTFail("Expected unknown tag error")
            }
        }
    }

    func testEvaluateMatch() {
        let spki = Data("spki".utf8)
        let fp = CertPin.spkiFingerprintBase64(spkiDer: spki)
        let record = "v=CERTPIN1; fp=\(fp)"
        let decision = CertPin.evaluate(record: record, spkiDer: spki)
        XCTAssertEqual(decision, .match)
    }

    func testEvaluateNoPolicyWhenMissingRecord() {
        let decision = CertPin.evaluate(record: nil, spkiDer: Data("spki".utf8))
        XCTAssertEqual(decision, .noPolicy)
    }

    func testEvaluateMalformed() {
        let decision = CertPin.evaluate(record: "v=CERTPIN1", spkiDer: Data("spki".utf8))
        XCTAssertEqual(decision, .malformed)
    }
}
