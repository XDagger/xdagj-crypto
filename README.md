# xdagj-crypto

[![Build Status](https://github.com/XDagger/xdagj-crypto/workflows/CI/badge.svg)](https://github.com/XDagger/xdagj-crypto/actions)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.xdag/xdagj-crypto/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.xdag/xdagj-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Java Version](https://img.shields.io/badge/Java-21+-blue.svg)](https://openjdk.java.net/)

A high-performance, security-focused cryptographic library designed specifically for the XDAG (DAG) ecosystem. This standalone library provides all essential cryptographic operations needed for XDAG applications, with a focus on security, performance, and ease of use.

## ✨ Features

### 🔐 **Cryptographic Operations**
- **ECDSA Signatures**: Traditional transaction signing with secp256k1
- **AES-256-GCM Encryption**: Authenticated encryption for secure data storage
- **Secure Random Generation**: Cryptographically secure random number generation

### 🏗️ **BIP Standards Support**
- **BIP32**: Hierarchical Deterministic (HD) key derivation
- **BIP39**: Mnemonic code generation and seed derivation
- **BIP44**: Multi-account hierarchy for deterministic wallets

### ⚡ **High Performance**
- **Zero-Copy Operations**: Built on Apache Tuweni Bytes for optimal memory usage
- **Bouncy Castle Integration**: Industry-standard cryptographic algorithms
- **Thread-Safe Design**: Concurrent operations support
- **Constant-Time Operations**: Protection against timing attacks

### 🛠️ **Utility Functions**
- **Address Generation**: XDAG-compatible address creation and validation
- **Base58Check Encoding**: Bitcoin-style address encoding with checksum
- **Hash Functions**: SHA-256, RIPEMD-160, double SHA-256, XDAG-specific digest
- **Data Encoding**: Hexadecimal and numeric conversions

### 🔮 **Future-Ready Architecture**
- **Extensible Design**: Modular architecture ready for emerging cryptographic standards
- **Zero-Knowledge Proof Ready**: Foundation for zk-SNARKs and zk-STARKs integration
- **Post-Quantum Prepared**: Framework for NIST-standardized quantum-resistant algorithms
- **Privacy-First**: Infrastructure for confidential transactions and private computations

## 📦 Installation

### Maven
```xml
<dependency>
    <groupId>io.xdag</groupId>
    <artifactId>xdagj-crypto</artifactId>
    <version>0.1.0</version>
</dependency>
```

### Gradle
```gradle
implementation 'io.xdag:xdagj-crypto:0.1.0'
```

## 🚀 Quick Start

### Generate a New Wallet
```java
import io.xdag.crypto.bip.*;
import io.xdag.crypto.keys.*;
import org.apache.tuweni.bytes.Bytes;

// Generate a new mnemonic
List<String> mnemonic = Bip39Mnemonic.generateMnemonic(128);
System.out.println("Mnemonic: " + String.join(" ", mnemonic));

// Create seed from mnemonic
Bytes seed = Bip39Mnemonic.mnemonicToSeed(mnemonic, "password");

// Create master key pair
Bip32Node masterNode = Bip44Wallet.createMasterKeyPair(seed.toArrayUnsafe());

// Derive XDAG key pair (account=0, addressIndex=0)
Bip32Node xdagNode = Bip44Wallet.deriveXdagKeyPair(masterNode, 0, 0);

// Generate XDAG address
Bytes20 address = AddressUtils.toBytesAddress(xdagNode.keyPair());
System.out.println("Address: " + address.toHexString());
```

### Sign and Verify Messages
```java
import io.xdag.crypto.keys.*;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

// Create a key pair
AsymmetricCipherKeyPair keyPair = Keys.createEcKeyPair();

// Sign a message hash
Bytes32 messageHash = Bytes32.fromHexString("0x1234567890abcdef...");
SignatureData signature = Sign.sign(messageHash, keyPair);

// Verify signature
ECPoint publicKey = ((ECPublicKeyParameters) keyPair.getPublic()).getQ();
boolean isValid = Sign.verify(messageHash, signature, publicKey);
System.out.println("Signature valid: " + isValid);
```



### Encrypt and Decrypt Data
```java
import io.xdag.crypto.encryption.Aes;
import io.xdag.crypto.core.SecureRandomProvider;
import org.apache.tuweni.bytes.Bytes;

// Generate encryption parameters
Bytes key = Bytes.wrap(SecureRandomProvider.getRandomBytes(32));
Bytes nonce = Bytes.wrap(SecureRandomProvider.getRandomBytes(12));
Bytes plainText = Bytes.wrap("Hello, XDAG!".getBytes());

// Encrypt
Bytes cipherText = Aes.encrypt(plainText, key, nonce);

// Decrypt
Bytes decrypted = Aes.decrypt(cipherText, key, nonce);
System.out.println("Decrypted: " + new String(decrypted.toArrayUnsafe()));
```

## 📚 API Overview

### Core Packages

| Package | Description | Key Classes |
|---------|-------------|-------------|
| `io.xdag.crypto.keys` | Key management and signatures | `Keys`, `Sign`, `AddressUtils` |
| `io.xdag.crypto.bip` | BIP standards implementation | `Bip44Wallet`, `Bip39Mnemonic`, `Bip32Node` |
| `io.xdag.crypto.hash` | Hash functions | `HashUtils`, `XdagSha256Digest` |
| `io.xdag.crypto.encryption` | Symmetric encryption | `Aes` |
| `io.xdag.crypto.encoding` | Data encoding utilities | `Base58` |
| `io.xdag.crypto.core` | Core providers | `CryptoProvider`, `SecureRandomProvider` |

### Key Classes

#### `Bip44Wallet`
```java
// Create master key from seed
Bip32Node master = Bip44Wallet.createMasterKeyPair(seed);

// Derive XDAG key pair
Bip32Node xdagKey = Bip44Wallet.deriveXdagKeyPair(master, account, addressIndex);

// Custom derivation path
int[] path = {44 | 0x80000000, 586 | 0x80000000, 0 | 0x80000000, 0, 0};
Bip32Node derived = Bip44Wallet.derivePath(master, path);
```

#### `Sign`
```java
// ECDSA: Sign message hash
SignatureData signature = Sign.sign(messageHash, keyPair);
boolean valid = Sign.verify(messageHash, signature, publicKey);

// Recover public key from ECDSA signature
ECPoint recovered = Sign.recoverPublicKeyFromSignature(v, r, s, messageHash);
```

#### `AddressUtils`
```java
// Generate address from key pair
Bytes20 address = AddressUtils.toBytesAddress(keyPair);

// Validate address format
boolean valid = AddressUtils.isValidAddress(addressString);
```

## 🏗️ Project Structure

```
src/main/java/io/xdag/crypto/
├── keys/           # Key management and signatures
│   ├── Keys.java
│   ├── Sign.java
│   └── AddressUtils.java
├── bip/            # BIP standards (32/39/44)
│   ├── Bip44Wallet.java
│   ├── Bip39Mnemonic.java
│   └── Bip32Node.java
├── hash/           # Hash algorithms
│   ├── HashUtils.java
│   └── XdagSha256Digest.java
├── encryption/     # Symmetric encryption
│   └── Aes.java
├── encoding/       # Data encoding
│   └── Base58.java
├── core/           # Core providers
│   ├── CryptoProvider.java
│   └── SecureRandomProvider.java
└── exception/      # Custom exceptions
    ├── CryptoException.java
    └── AddressFormatException.java
```

## 🔧 Building from Source

### Prerequisites
- **Java 21+** (JDK with preview features support)
- **Maven 3.8+**

### Build Commands
```bash
# Clone the repository
git clone https://github.com/XDagger/xdagj-crypto.git
cd xdagj-crypto

# Compile and run tests
mvn clean test

# Build JAR
mvn clean package

# Generate documentation
mvn javadoc:javadoc
```

### Testing
```bash
# Run all tests
mvn test

# Run tests with coverage
mvn clean test jacoco:report

# Run specific test class
mvn test -Dtest=Bip44WalletTest
```

## 🛡️ Security Features

- **Constant-Time Operations**: Protection against timing attacks
- **Secure Random Generation**: Cryptographically secure entropy sources
- **Memory Safety**: Secure handling of sensitive data
- **Industry Standards**: Compliance with BIP specifications and cryptographic standards
- **Audited Libraries**: Built on well-tested Bouncy Castle cryptography
- **Future-Proof Security**: Architecture designed to integrate quantum-resistant algorithms
- **Privacy-Preserving**: Foundation for zero-knowledge proof systems and confidential transactions

## 🔗 Dependencies

- **Bouncy Castle** (`bcprov-jdk18on`): Core cryptographic operations
- **Apache Tuweni Bytes**: High-performance byte array operations
- **SLF4J**: Logging abstraction

## 📖 Documentation

- [Javadoc API Reference](https://xdagger.github.io/xdagj-crypto/apidocs/)
- [Design Document](DESIGN.md) (Chinese)
- [Examples](examples/) - Additional usage examples

### Technical References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Zero-Knowledge Proof Systems](https://zkp.science/) - For future ZKP integration
- [CRYSTALS Cryptographic Suite](https://pq-crystals.org/) - Post-quantum algorithms

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`mvn test`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Code Style
- Follow Java naming conventions (camelCase for methods and fields)
- Use meaningful variable and method names
- Add comprehensive Javadoc comments for public APIs
- Write unit tests for all new functionality

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎯 Roadmap

- [x] **v0.1.0**: Core cryptographic operations (ECDSA, BIP32/39/44, AES-GCM)
- [ ] **v0.2.0**: Enhanced security features and optimizations 
- [ ] **v0.3.0**: Performance optimizations and batch operations
- [ ] **v0.4.0**: Zero-Knowledge Proof primitives (zk-SNARKs, zk-STARKs)
- [ ] **v0.5.0**: Post-quantum cryptography algorithms (CRYSTALS-Dilithium, CRYSTALS-Kyber)
- [ ] **v0.6.0**: Privacy-preserving features and confidential transactions
- [ ] **v1.0.0**: Stable API release with comprehensive security audit

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/XDagger/xdagj-crypto/issues)
- **Discussions**: [GitHub Discussions](https://github.com/XDagger/xdagj-crypto/discussions)
- **XDAG Community**: [Official XDAG Website](https://xdag.io)

---

**Built with ❤️ for the XDAG community** 