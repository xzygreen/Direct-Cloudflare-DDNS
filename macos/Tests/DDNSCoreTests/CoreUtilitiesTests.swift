import XCTest
@testable import DDNSCore

final class CoreUtilitiesTests: XCTestCase {
    func testAddressParsing() {
        let found = AddressParser.addresses(
            in: "检测到公网 IPv4：8.8.8.8；IPv6：2606:4700:4700::1111"
        )
        XCTAssertEqual(found.v4, "8.8.8.8")
        XCTAssertEqual(found.v6, "2606:4700:4700::1111")
    }

    func testAddressParsingWithASCIISeparators() {
        let found = AddressParser.addresses(
            in: "IPv4:8.8.4.4; IPv6:2001:4860:4860::8888"
        )
        XCTAssertEqual(found.v4, "8.8.4.4")
        XCTAssertEqual(found.v6, "2001:4860:4860::8888")
    }

    func testIPv6ValidationRejectsMalformedValues() {
        XCTAssertTrue(AddressParser.isIPv6("2606:4700:4700::1111"))
        XCTAssertFalse(AddressParser.isIPv6("dead:beef"))
        XCTAssertFalse(AddressParser.isIPv6("::::"))
    }

    func testDomainNormalizationAndWildcard() throws {
        XCTAssertEqual(
            try DomainValidator.normalized("Home.Example.COM.", allowWildcard: false),
            "home.example.com"
        )
        XCTAssertEqual(
            try DomainValidator.normalized("*.example.com", allowWildcard: true),
            "*.example.com"
        )
    }

    func testDomainRejectsUnsafeLabels() {
        for value in ["bad name.example.com", "-home.example.com", "home-.example.com"] {
            XCTAssertThrowsError(try DomainValidator.normalized(value, allowWildcard: false))
        }
        XCTAssertThrowsError(try DomainValidator.normalized("a.*.example.com", allowWildcard: true))
    }
}
