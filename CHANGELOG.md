# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2025-10-22

### Security
- **CRITICAL**: Fixed PublicKey constructor accepting point-at-infinity
  - Point-at-infinity is now explicitly rejected before validation
  - Prevents creation of invalid public keys that could lead to:
    - Invalid XDAG addresses
    - Signature verification failures
    - Blockchain consensus issues
  - Added explicit `point.isInfinity()` check in constructor

### Added
- Official BIP-0032 test vectors (13 tests) from Bitcoin specification
- Official BIP-0039 test vectors (5 tests) from Trezor specification
- `PublicKeyInfinityTest` - Validates point-at-infinity rejection
- `XdagSha256DigestStateTest` - Validates digest state robustness (5 tests)

### Fixed
- Fixed BigInteger.toString(16) losing leading zeros in test assertions
  - Changed to use `PrivateKey.toUnprefixedHex()` for correct 32-byte padding
  - Discovered through BIP-0032 official test vectors

### Changed
- Renamed all test methods to follow JUnit 5 conventions
  - Pattern: `testXxx()` → `shouldXxx()`
  - Applied consistently across all 19 test files
  - Examples: `testEncodeDecode()` → `shouldEncodeAndDecode()`

### Testing
- **Total Tests**: 207 tests (6 new tests added)
- **Coverage**: 95%+ line coverage maintained
- **All tests passing**: ✅ 207/207

---

## [0.1.3] - 2024-XX-XX

### Changed
- Version bump to 0.1.3

### Fixed
- Cleaned up dependencies and corrected documentation
- Changed AES-GCM to AES-CBC for xdagj wallet file compatibility

---

## [0.1.2] - 2024-XX-XX

### Changed
- Initial release with core cryptographic functionality

---

## [Unreleased]

### Planned
- Strengthen validation in `Signer.decompressKey()` for edge cases
- Replace magic numbers with named constants for better maintainability
- Consider professional cryptographic audit for production use

---

[0.1.4]: https://github.com/XDagger/xdagj-crypto/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/XDagger/xdagj-crypto/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/XDagger/xdagj-crypto/releases/tag/v0.1.2
