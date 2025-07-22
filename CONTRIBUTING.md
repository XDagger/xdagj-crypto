# Contributing to xdagj-crypto

We love your input! We want to make contributing to xdagj-crypto as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

### Pull Requests

Pull requests are the best way to propose changes to the codebase. We actively welcome your pull requests:

1. **Fork the repository** and create your branch from `main`.
2. **Make your changes** and ensure they follow our coding standards.
3. **Add tests** if you've added code that should be tested.
4. **Ensure the test suite passes** by running `mvn test`.
5. **Update documentation** if you've changed APIs.
6. **Follow our code style** and naming conventions.
7. **Submit your pull request**!

### Code Style

#### Java Conventions
- **Naming**: Use camelCase for methods and fields, PascalCase for classes
- **Javadoc**: Add comprehensive documentation for all public APIs
- **Testing**: Write unit tests for all new functionality
- **Security**: Follow secure coding practices for cryptographic operations

#### Example:
```java
/**
 * Signs a message hash using ECDSA with the secp256k1 curve.
 *
 * @param messageHash the hash of the message to sign (32 bytes)
 * @param keyPair the key pair to use for signing
 * @return the signature data containing r, s, and recovery ID
 * @throws IllegalArgumentException if parameters are invalid
 */
public static SignatureData signMessageHash(Bytes32 messageHash, AsymmetricCipherKeyPair keyPair) {
    // Implementation...
}
```

#### Testing Standards
```java
class ExampleServiceTest {
    
    @Test
    void shouldHandleValidInput() {
        // Given
        Bytes32 input = Bytes32.fromHexString("0x123...");
        
        // When
        Bytes result = ExampleService.process(input);
        
        // Then
        assertThat(result).isNotNull();
    }
}
```

### Commit Messages

Write clear, concise commit messages:
- Use the imperative mood ("Add feature" not "Added feature")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

**Good examples:**
```
Add Schnorr signature verification with BIP340 test vectors

- Implement BIP340-compliant signature verification
- Add comprehensive test cases from official specification
- Ensure constant-time operations for security

Fixes #123
```

## Testing

### Running Tests
```bash
# Run all tests
mvn test

# Run tests with coverage
mvn clean test jacoco:report

# Run specific test class
mvn test -Dtest=Bip44WalletTest

# Run tests in specific package
mvn test -Dtest="io.xdag.crypto.keys.*"
```

### Test Requirements
- **Unit tests** for all public methods
- **Integration tests** for complex workflows
- **Test vectors** from official specifications (BIP39, BIP32, BIP340, etc.)
- **Edge cases** and error conditions
- **Performance benchmarks** for critical paths

### Test Categories
- 🧪 **Unit Tests**: Test individual components in isolation
- 🔗 **Integration Tests**: Test component interactions
- 📊 **Performance Tests**: Benchmark critical operations
- 🛡️ **Security Tests**: Verify cryptographic correctness

## Security Considerations

Since this is a cryptographic library, security is paramount:

### Reporting Security Issues
- **DO NOT** report security vulnerabilities in public issues
- Send security reports to: [security@xdag.io](mailto:security@xdag.io)
- Include detailed reproduction steps and impact assessment

### Security Guidelines
- Use **constant-time algorithms** to prevent timing attacks
- Implement **secure memory handling** for sensitive data
- Follow **cryptographic best practices** and industry standards
- Validate **all inputs** and handle edge cases securely
- Use **well-tested libraries** (Bouncy Castle) for core operations

## Documentation

### API Documentation
- Add **Javadoc comments** for all public classes and methods
- Include **usage examples** in documentation
- Document **thread-safety** characteristics
- Explain **security considerations** for cryptographic methods

### Examples
- Provide **working code examples** for common use cases
- Include **test vectors** from official specifications
- Demonstrate **best practices** and secure usage patterns

## Issue Guidelines

### Bug Reports
Create detailed bug reports with:
- **Environment**: Java version, OS, library version
- **Reproduction steps**: Minimal code to reproduce the issue
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Logs/stacktraces**: Relevant error output

### Feature Requests
For new features, provide:
- **Use case**: Why this feature is needed
- **Proposed API**: How the feature should work
- **Alternatives**: Other solutions you've considered
- **Security impact**: Any cryptographic security considerations

## Code Review Process

All submissions require review before merging:

1. **Automated checks** must pass (tests, linting, security scans)
2. **Code review** by at least one maintainer
3. **Security review** for cryptographic changes
4. **Documentation review** for API changes

## Recognition

Contributors will be recognized in:
- Release notes for significant contributions
- README.md contributor section
- Git commit history and GitHub contributors page

## Questions?

Feel free to ask questions by:
- Opening a [GitHub Discussion](https://github.com/XDagger/xdagj-crypto/discussions)
- Creating an issue with the "question" label
- Reaching out to maintainers

---

**Thank you for contributing to xdagj-crypto!** 🚀 