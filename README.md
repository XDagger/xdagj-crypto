# XDAG Java Cryptographic Library

[![Build Status](https://github.com/XDagger/xdagj-crypto/workflows/CI/badge.svg)](https://github.com/XDagger/xdagj-crypto/actions)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.xdag/xdagj-crypto/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.xdag/xdagj-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Java Version](https://img.shields.io/badge/Java-21+-blue.svg)](https://openjdk.java.net/)

A production-grade cryptographic library for XDAG blockchain applications with focus on security, performance, and developer experience.

## 🆕 What's New in v0.1.1

- **Enhanced XDAG Compatibility**: Added `PublicKey.fromXCoordinate()` method for XDAG's 32-byte x-coordinate + y-bit format
- **Simplified HD Wallet API**: Direct key pair generation from mnemonic phrases
- **Improved Documentation**: Fixed Javadoc warnings and enhanced API documentation
- **Optimized Dependencies**: Removed unnecessary configurations for better performance

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

**Requirements**: Java 21+

## 🚀 Quick Start

### 1. Basic Key Operations

```java
import io.xdag.crypto.keys.*;

// Generate key pair and address
ECKeyPair keyPair = ECKeyPair.generate();
String address = keyPair.toBase58Address();

// XDAG compatibility (NEW v0.1.1): Create from x-coordinate + y-bit
PublicKey xdagKey = PublicKey.fromXCoordinate(xCoordinate, yBit);
```

### 2. HD Wallet (BIP32/44)

```java
import io.xdag.crypto.bip.*;

// Generate mnemonic and derive key pairs
String mnemonic = Bip39Mnemonic.generateString();

// NEW v0.1.1: Simplified API for basic use cases
ECKeyPair keyPair = Bip44Wallet.createKeyPairFromMnemonic(mnemonic);

// Advanced: BIP44 derivation path m/44'/586'/0'/0/0
Bytes seed = Bip39Mnemonic.toSeed(mnemonic);
Bip32Key masterKey = Bip44Wallet.createMasterKey(seed.toArrayUnsafe());
Bip32Key accountKey = Bip44Wallet.deriveXdagKey(masterKey, 0, 0);
```

### 3. Digital Signatures & Encryption

```java
import io.xdag.crypto.keys.*;
import io.xdag.crypto.encryption.Aes;

// Sign and verify messages  
Signature signature = Signer.sign(messageHash, keyPair);
boolean valid = Signer.verify(messageHash, signature, keyPair.getPublicKey());

// AES-256-GCM encryption
Bytes cipherText = Aes.encrypt(plainText, encryptionKey, nonce);
Bytes decrypted = Aes.decrypt(cipherText, encryptionKey, nonce);
```

## 🏗️ Core Features

- **Elliptic Curve Cryptography**: ECDSA with secp256k1 curve
- **Hierarchical Deterministic Wallets**: BIP32/BIP39/BIP44 implementation  
- **Symmetric Encryption**: AES-256-GCM authenticated encryption
- **Hash Functions**: SHA-256, RIPEMD-160, HMAC operations
- **Address Generation**: XDAG-compatible Base58 addresses
- **XDAG Integration**: Native support for XDAG public key formats

## 🛡️ Security

- **Cryptographic Standards**: ECDSA (secp256k1), AES-256-GCM, SHA-256, PBKDF2
- **Constant-Time Operations**: Prevents timing attacks
- **Secure Random Generation**: Platform-optimal entropy sources  
- **Input Validation**: Comprehensive validation with detailed error messages
- **Thread Safety**: All operations are thread-safe by design

## 🔗 Dependencies

- **Consensys Tuweni**: High-performance byte operations
- **Bouncy Castle**: Cryptographic implementations  
- **SLF4J**: Logging framework

## 📊 Key Features v0.1.1

### New XDAG Compatibility
```java
// Create public key from XDAG's x-coordinate + y-bit format
PublicKey xdagKey = PublicKey.fromXCoordinate(xCoordinate, yBit);
```

### Simplified HD Wallet API
```java
// Direct key pair generation from mnemonic
ECKeyPair keyPair = Bip44Wallet.createKeyPairFromMnemonic(mnemonic);
```

For complete API documentation, see [JavaDoc](https://xdagger.github.io/xdagj-crypto/)

## 🏗️ Building from Source

```bash
# Prerequisites: Java 21+, Maven 3.8+
git clone https://github.com/XDagger/xdagj-crypto.git
cd xdagj-crypto

# Run tests and build
mvn clean test package
```

## 🤝 Contributing

We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details.

**Development Standards**:
- Code Coverage: Minimum 95% line coverage
- Documentation: Comprehensive Javadoc for all public APIs
- Testing: Unit tests for all functionality
- Security: Regular dependency vulnerability scanning

## 📄 License

Licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- **[xdagj](https://github.com/XDagger/xdagj)**: Java implementation of XDAG blockchain
- **[xdagj-p2p](https://github.com/XDagger/xdagj-p2p)**: Peer-to-peer networking layer

---

**Built with ❤️ by the XDAG Development Team** 