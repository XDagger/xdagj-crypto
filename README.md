# XDAG Java Cryptographic Library

[![Build Status](https://github.com/XDagger/xdagj-crypto/workflows/CI/badge.svg)](https://github.com/XDagger/xdagj-crypto/actions)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.xdag/xdagj-crypto/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.xdag/xdagj-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Java Version](https://img.shields.io/badge/Java-21+-blue.svg)](https://openjdk.java.net/)
[![Codecov](https://codecov.io/gh/XDagger/xdagj-crypto/branch/master/graph/badge.svg)](https://codecov.io/gh/XDagger/xdagj-crypto)

A production-grade, high-performance cryptographic library designed specifically for XDAG blockchain applications. Built with security, performance, and developer experience as first-class concerns.

## 🎯 Design Philosophy

| Principle | Description | Benefits |
|-----------|-------------|----------|
| **Security First** | Constant-time algorithms, secure memory handling, cryptographic best practices | Prevents timing attacks and side-channel vulnerabilities |
| **Performance Optimized** | Zero-copy operations, efficient memory management, minimal allocations | Maximum throughput with minimal resource usage |
| **Developer Centric** | Type-safe APIs, comprehensive error handling, intuitive method signatures | Prevents common cryptographic mistakes and improves productivity |

## 🏗️ Architecture

### Core Design Principles

| Principle | Implementation | Advantage |
|-----------|----------------|-----------|
| **Immutable Data Structures** | All cryptographic objects are immutable | Prevents accidental modification of sensitive data |
| **Type Safety** | Strong typing with dedicated classes (PrivateKey, PublicKey, etc.) | Prevents incorrect usage patterns and compile-time safety |
| **Zero-Copy Operations** | Extensive use of Consensys Tuweni Bytes | High-performance byte manipulation without unnecessary copying |
| **Thread Safety** | All operations are thread-safe by design | Safe concurrent usage without additional synchronization |
| **Fail-Fast Validation** | Input validation with descriptive error messages | Catches issues early in development with clear feedback |

### Package Architecture

```
io.xdag.crypto/
├── core/                   # Cryptographic providers and validation
│   ├── CryptoProvider      # Unified BC provider and secure random
│   └── KeyValidator        # Input validation utilities
├── keys/                   # Elliptic curve cryptography
│   ├── ECKeyPair          # secp256k1 key pair management
│   ├── PrivateKey         # Private key operations and derivation
│   ├── PublicKey          # Public key operations and verification
│   ├── Signature          # ECDSA signature representation
│   ├── Signer             # Digital signature operations
│   └── AddressUtils       # XDAG address generation/validation
├── bip/                    # Bitcoin Improvement Proposals implementation
│   ├── Bip39Mnemonic      # BIP39 mnemonic phrase generation/validation
│   ├── Bip44Wallet        # BIP44 hierarchical deterministic wallets
│   └── Bip32Key           # BIP32 extended key representation
├── hash/                   # Cryptographic hash functions
│   ├── HashUtils          # SHA-256, RIPEMD-160, HMAC operations
│   └── XdagSha256Digest   # XDAG-specific double SHA-256 with endianness
├── encryption/             # Symmetric encryption
│   └── Aes                # AES-256-GCM authenticated encryption
├── encoding/               # Binary encoding schemes
│   └── Base58             # Base58 and Base58Check encoding
└── exception/              # Domain-specific exceptions
    ├── CryptoException     # General cryptographic errors
    └── AddressFormatException # Address validation errors
```

## 📦 Installation

### Maven
```xml
<dependency>
    <groupId>io.xdag</groupId>
    <artifactId>xdagj-crypto</artifactId>
    <version>0.1.1</version>
</dependency>
```

### Gradle
```gradle
implementation 'io.xdag:xdagj-crypto:0.1.1'
```

### System Requirements

- **Java**: 21+ (LTS recommended)
- **Supported Platforms**: Linux, macOS, Windows
- **Memory**: Minimum 64MB heap for basic operations
- **Dependencies**: Minimal transitive runtime dependencies - uses Consensys Tuweni, Bouncy Castle, and SLF4J

## 🚀 Quick Start Guide

### 1. Basic Key Operations

```java
import io.xdag.crypto.keys.*;
import io.xdag.crypto.exception.CryptoException;

try {
    // Generate cryptographically secure key pair
    ECKeyPair keyPair = ECKeyPair.generate();
    
    // Extract components
    PrivateKey privateKey = keyPair.getPrivateKey();
    PublicKey publicKey = keyPair.getPublicKey();
    
    // Generate XDAG address using hash160 (SHA256 + RIPEMD160)
    String address = keyPair.toBase58Address();
    
    // Export for storage (32-byte private key)
    String privateKeyHex = privateKey.toHex();
    
    // Import from stored key
    PrivateKey imported = PrivateKey.fromHex(privateKeyHex);
    
} catch (CryptoException e) {
    // Handle cryptographic errors with detailed messages
    log.error("Key operation failed: {}", e.getMessage());
}
```

### 2. HD Wallet Implementation (BIP32/44)

```java
import io.xdag.crypto.bip.*;
import io.xdag.crypto.exception.CryptoException;
import org.apache.tuweni.bytes.Bytes;

try {
    // Generate cryptographically secure 12-word mnemonic (128-bit entropy)
    String mnemonic = Bip39Mnemonic.generateString();
    
    // Validate mnemonic checksum
    if (!Bip39Mnemonic.isValid(mnemonic)) {
        throw new IllegalArgumentException("Invalid mnemonic checksum");
    }
    
    // Derive 512-bit seed using PBKDF2 with 2048 iterations
    Bytes seed = Bip39Mnemonic.toSeed(mnemonic);
    // Optional: add passphrase for additional security
    Bytes seedWithPassphrase = Bip39Mnemonic.toSeed(mnemonic, "secure_passphrase");
    
    // Create master key using HMAC-SHA512
    Bip32Key masterKey = Bip44Wallet.createMasterKey(seed.toArrayUnsafe());
    
    // Derive XDAG account keys following BIP44 standard
    // Path: m/44'/586'/account'/0/addressIndex (586 is XDAG's coin type)
    for (int i = 0; i < 10; i++) {
        Bip32Key accountKey = Bip44Wallet.deriveXdagKey(masterKey, 0, i);
        String address = accountKey.keyPair().toBase58Address();
        System.out.printf("Address %d: %s%n", i, address);
    }
    
} catch (CryptoException e) {
    log.error("HD wallet operation failed: {}", e.getMessage());
}
```

### 3. Digital Signatures (ECDSA with secp256k1)

```java
import io.xdag.crypto.keys.*;
import org.apache.tuweni.bytes.Bytes32;

// Message to sign (typically a hash)
Bytes32 messageHash = Bytes32.fromHexString(
    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

ECKeyPair signerKeyPair = ECKeyPair.generate();

try {
    // Create deterministic ECDSA signature (RFC 6979)
    Signature signature = Signer.sign(messageHash, signerKeyPair);
    
    // Verify signature
    boolean isValid = Signer.verify(messageHash, signature, signerKeyPair.getPublicKey());
    assert isValid : "Signature verification failed";
    
    // Recover public key from signature (useful for address recovery)
    PublicKey recoveredKey = Signer.recoverPublicKey(messageHash, signature);
    assert recoveredKey.equals(signerKeyPair.getPublicKey()) : "Key recovery failed";
    
    // Signature components for serialization
    String r = signature.getR().toString(16);
    String s = signature.getS().toString(16);
    int recoveryId = signature.getRecoveryId();
    
} catch (CryptoException e) {
    log.error("Signature operation failed: {}", e.getMessage());
}
```

### 4. Authenticated Encryption (AES-256-GCM)

```java
import io.xdag.crypto.encryption.Aes;
import io.xdag.crypto.core.CryptoProvider;
import org.apache.tuweni.bytes.Bytes;

try {
    // Generate cryptographically secure parameters
    Bytes encryptionKey = Bytes.wrap(CryptoProvider.getRandomBytes(32)); // 256-bit key
    Bytes nonce = Bytes.wrap(CryptoProvider.getRandomBytes(12));         // 96-bit nonce
    
    Bytes plainText = Bytes.of("Confidential XDAG transaction data".getBytes());
    
    // Encrypt with authentication tag
    Bytes cipherText = Aes.encrypt(plainText, encryptionKey, nonce);
    
    // Decrypt and verify authenticity
    Bytes decrypted = Aes.decrypt(cipherText, encryptionKey, nonce);
    
    assert plainText.equals(decrypted) : "Decryption failed";
    
} catch (Exception e) {
    log.error("Encryption operation failed: {}", e.getMessage());
}
```

## 🛡️ Security Features

### Cryptographic Standards Compliance

| Algorithm | Standard | Implementation | Key Size |
|-----------|----------|----------------|----------|
| **ECDSA** | SEC 2, RFC 6979 | secp256k1 curve | 256-bit |
| **AES-GCM** | NIST SP 800-38D | Authenticated encryption | 256-bit |
| **SHA-256** | FIPS 180-4 | Message digest | 256-bit output |
| **RIPEMD-160** | ISO/IEC 10118-3 | Address generation | 160-bit output |
| **PBKDF2** | RFC 2898 | Key derivation | 2048 iterations |
| **HMAC** | RFC 2104 | Message authentication | SHA-512 based |

### Security Measures

- **Constant-Time Operations**: Critical operations use constant-time algorithms to prevent timing attacks
- **Secure Random Generation**: Uses platform-optimal entropy sources with automatic reseeding
- **Memory Safety**: Sensitive data is handled securely with proper cleanup where possible
- **Input Validation**: Comprehensive validation with fail-fast error reporting
- **Side-Channel Resistance**: Implementations avoid data-dependent branches and memory access patterns

### Best Practices Integration

```java
// Example: Secure key generation with validation
try {
    PrivateKey privateKey = PrivateKey.generateRandom();
    
    // Automatic validation ensures key is in valid range [1, n-1]
    // where n is the secp256k1 curve order
    
    // Export with secure formatting
    String keyHex = privateKey.toHex(); // Always 64 hex characters
    
    // Import with validation
    PrivateKey imported = PrivateKey.fromHex(keyHex);
    
} catch (CryptoException e) {
    // Handle specific crypto errors
    log.error("Key generation failed: {}", e.getMessage());
}
```

## 🔗 Dependencies

### Runtime Dependencies

```xml
<!-- Core cryptographic operations - Tuweni byte manipulation -->
<dependency>
    <groupId>io.consensys.tuweni</groupId>
    <artifactId>tuweni-bytes</artifactId>
    <version>2.7.0</version>
</dependency>

<!-- Additional Tuweni utilities -->
<dependency>
    <groupId>io.consensys.tuweni</groupId>
    <artifactId>tuweni-units</artifactId>
    <version>2.7.0</version>
</dependency>

<dependency>
    <groupId>io.consensys.tuweni</groupId>
    <artifactId>tuweni-io</artifactId>
    <version>2.7.0</version>
</dependency>

<!-- Bouncy Castle cryptographic provider -->
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk18on</artifactId>
    <version>1.80</version>
</dependency>

<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpkix-jdk18on</artifactId>
    <version>1.80</version>
</dependency>

<!-- Logging framework -->
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-api</artifactId>
    <version>2.0.17</version>
</dependency>

<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-simple</artifactId>
    <version>2.0.17</version>
</dependency>
```

### Development Dependencies

```xml
<!-- Development Dependencies -->
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <version>1.18.38</version>
    <scope>provided</scope>
</dependency>

<!-- Test Dependencies -->
<dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <version>5.12.2</version>
    <scope>test</scope>
</dependency>
```

**Key Features:**
- **Lombok** (compile-time): Reduces boilerplate code generation
- **JUnit Jupiter**: Modern testing framework with comprehensive assertion library
- **Test Coverage**: >95% line coverage across all modules

## 📊 API Reference

### Core Cryptographic Operations

#### ECKeyPair
```java
// Factory methods
public static ECKeyPair generate() throws CryptoException
public static ECKeyPair fromPrivateKey(PrivateKey privateKey)

// Key access
public PrivateKey getPrivateKey()
public PublicKey getPublicKey()

// Address generation
public String toBase58Address()
```

#### Signer
```java
// Signature operations
public static Signature sign(Bytes32 messageHash, ECKeyPair keyPair) throws CryptoException
public static Signature sign(Bytes32 messageHash, PrivateKey privateKey) throws CryptoException

// Verification
public static boolean verify(Bytes32 messageHash, Signature signature, PublicKey publicKey)

// Key recovery
public static PublicKey recoverPublicKey(Bytes32 messageHash, Signature signature) 
    throws CryptoException
```

#### Bip39Mnemonic
```java
// Mnemonic generation
public static String generateString() throws CryptoException

// Validation
public static boolean isValid(String mnemonic)

// Seed derivation
public static Bytes toSeed(String mnemonic) throws CryptoException
public static Bytes toSeed(String mnemonic, String passphrase) throws CryptoException
```

### Error Handling

All cryptographic operations throw `CryptoException` with detailed error messages:

```java
try {
    ECKeyPair keyPair = ECKeyPair.generate();
} catch (CryptoException e) {
    // Specific error messages for debugging:
    // - "Failed to generate cryptographically secure random key"
    // - "Private key value out of valid range"
    // - "Elliptic curve point validation failed"
    log.error("Cryptographic operation failed", e);
}
```

## 🏗️ Building from Source

```bash
# Prerequisites: Java 21+, Maven 3.8+
git clone https://github.com/XDagger/xdagj-crypto.git
cd xdagj-crypto

# Run full test suite
mvn clean test

# Generate code coverage report
mvn jacoco:report

# Build distributable JAR
mvn clean package

# Generate API documentation
mvn javadoc:javadoc
```

## 🤝 Contributing

We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Standards

- **Code Coverage**: Minimum 95% line coverage required
- **Documentation**: All public APIs must have comprehensive Javadoc
- **Testing**: Comprehensive unit tests for all functionality
- **Code Quality**: SpotBugs, PMD, and Checkstyle validation
- **Security**: Regular dependency vulnerability scanning

### Reporting Issues

- **Security Issues**: Email security@xdag.io (GPG key available)
- **Bug Reports**: [GitHub Issues](https://github.com/XDagger/xdagj-crypto/issues)
- **Feature Requests**: [GitHub Discussions](https://github.com/XDagger/xdagj-crypto/discussions)

## 📄 License

Licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- **[xdagj](https://github.com/XDagger/xdagj)**: Java implementation of XDAG blockchain
- **[xdagj-p2p](https://github.com/XDagger/xdagj-p2p)**: Peer-to-peer networking layer

---

**Built with ❤️ by the XDAG Development Team** 