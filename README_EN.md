# EntanglementLib

[![Version](https://img.shields.io/badge/version-1.1.0%20Alpha-blue?style=for-the-badge)](https://github.com/Quant-Off/entanglementlib)
[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial%20License%201.0.0-green?style=for-the-badge)](LICENSE)
[![Language](https://img.shields.io/badge/language-Java-orange?style=for-the-badge)](https://github.com/Quant-Off/entanglementlib)

![EntanglementLib](entanglementlib-logo.png)

EntanglementLib is a high-performance security and utility library designed based on Post-Quantum Cryptography (PQC) technology. This library aims to provide the highest level of security and system stability in response to the evolving digital threat landscape.

> [Korean README](README.md)

## Core Philosophy

All designs of EntanglementLib prioritize 'security' for 'military-grade security' and 'establishing secure infrastructure in financial and large-scale enterprise environments' as the foremost principle. EntanglementLib is implemented to fundamentally prevent potential security vulnerabilities and ensure data integrity. The second core value is 'stability'. To ensure predictable and consistent performance, Rust native operations are applied to maximize memory efficiency very safely, and a systematic error (or exception) handling mechanism is equipped.

## Strengths

EntanglementLib possesses the following strengths:

1. **Anti-Data Remanence and Memory Erasure**
   - We accurately identified that Java's memory management model, the Garbage Collector (GC), can be vulnerable to security threats, and equipped technology to technically overcome this.
   - For this technology, we designed it to safely erase data using the [`entlib-native` native library](https://github.com/Quant-Off/entlib-native).
   - We provide a [Data Container feature](https://github.com/Quant-Off/entanglementlib/blob/master/src/main/java/space/qu4nt/entanglementlib/entlibnative/SensitiveDataContainer.java) to safely manage all sensitive information.
2. **Compliance with Latest PQC Standards**
   - It supports the latest algorithms standardized by NIST such as ML-KEM, ML-DSA, and SLH-DSA according to FIPS 203, 204, and 205, as well as classical algorithms like AES, ARIA, and ChaCha20, processing them natively to enable secure operations.
3. **Architecture and Design Patterns**
   - Factory patterns and interfaces are clearly separated. [Cryptographic algorithms can be called and used strategically](https://github.com/Quant-Off/entanglementlib/tree/master/src/main/java/space/qu4nt/entanglementlib/security/crypto).
4. **Exception Handling**
   - We ensured that standard exceptions are not thrown as is. They are wrapped in EntanglementLib's custom exception classes to provide clear context.
   - If a problem is discovered from a security perspective, the system is designed to suggest a solution and defend against concerning attacks (hacking).

## Key Features

EntanglementLib includes powerful encryption features and utilities for improving development productivity.

| Module | Technical Specification |
| :--- | :--- |
| `security.crypto` | Provides Post-Quantum Cryptography (PQC) and modern encryption algorithms.<br/>- **PQC (NIST Standards)**: Supports `ML-DSA` (Digital Signature Algorithm), `ML-KEM` (Key Encapsulation Mechanism), and `SLH-DSA` to build a security system responding to the quantum computing era.<br/>- **Symmetric Key Encryption**: Supports `ChaCha20-Poly1305` AEAD (Authenticated Encryption with Associated Data) to provide high levels of confidentiality and integrity simultaneously.<br/>- **High-Performance Computing**: Major algorithms utilize SIMD (Single Instruction, Multiple Data) instruction sets to maximize parallel processing and optimize calculation speed.<br/>- **Strategy Pattern**: Algorithms can be flexibly registered and used through `RegistrableStrategy` and `EntLibCryptoRegistry`. |
| `security.communication` | Provides session and TLS-related functions for secure communication.<br/>- **Session Management**: Creates and manages secure sessions through `Session`, `Participant`, `SessionConfig`, etc.<br/>- **TLS Support**: Builds TLS-based secure communication channels through `Server`, `ServerConfig`, etc. |
| `entlibnative` | Handles linkage with native libraries.<br/>- **Data Protection**: Safely manages and erases sensitive data through `SensitiveDataContainer`.<br/>- **Native Linkage**: Loads and uses high-performance native libraries written in Rust, etc., through `NativeLinkerManager`. |
| `util` | Provides high-performance utilities considering security and development convenience.<br/>- **I/O and Chunk Processing**: Efficiently processes large files and data through `EntFile`, `ChunkProcessor`, etc.<br/>- **Security Utilities**: Safely handles passwords and sensitive strings through `Password`, `SecureCharBuffer`, etc.<br/>- **Others**: Provides various utility classes such as `Hex`, `Hash`, `Async`, etc. |
| `exception` | Provides a systematic exception hierarchy for stable error handling.<br/>- **Security Exceptions**: Clearly handles security-related errors through `EntLibSecureException` and its subclasses.<br/>- **Encryption Exceptions**: Manages errors occurring during the encryption process by subdividing them through `EntLibCryptoException`, etc.<br/>- **Fatal Errors**: Defines fatal system errors through `EntLibError` and its subclasses. |

## Technical Specifications

Technical specifications on how EntanglementLib interacts with native libraries and how security operations are performed natively are written [here](TECHNICAL.md).

## Benchmarking Records

We are performing bridge benchmarking for various operations, such as nanosecond delays occurring when calling Rust native functions using the FFM API in EntanglementLib. These tasks are directly related to performance and security and play an important role in creating optimal code.

EntanglementLib's benchmarking is conducted in the [`native-benchmark`](native-benchmark) Rust project, and benchmarking records are written [here](NATIVE_BENCHMARK.md).

## Getting Started

### 1. Requirements

EntanglementLib was developed in the following environment. Detailed testing for other versions has not been conducted.

- Java 25
- Gradle 9.2.0

EntanglementLib uses Java 25 or higher to stably use the algorithms included in NIST FIPS 203, 204, and 205 standardization.

### 2. Environment Variable Configuration

The following environment variable settings are required for the normal operation of `EntanglementLib`.

| Variable Name | Description | Default | Required |
| :--- | :--- | :--- | :--- |
| `ENTLIB_NATIVE_BIN` | Specifies the directory path containing the native library binaries. | - | Required |
| `ENTANGLEMENT_HOME_DIR` | Specifies the directory path where resources used inside EntanglementLib will be stored. | - | Required |

```bash
# Example: Linux/macOS
export ENTLIB_NATIVE_BIN="/path/to/entlib-native/release"
export ENTANGLEMENT_HOME_DIR="/path/to/entanglementlib"
```

```bash
# Example: Windows
setx ENTLIB_NATIVE_BIN "C:\path\to\entlib-native\release"
setx ENTANGLEMENT_HOME_DIR "C:\path\to\entanglementlib"
```

### 3. Clone Repository or Use Maven Repository

You can clone the repository via the following command:

```shell
$ git clone https://github.com/Quant-Off/entanglementlib.git
$ cd entanglementlib
```

If you want to register it as a dependency, you can simply use the `Maven` repository.

#### Maven Project

```xml
<dependencies>
    <dependency>
        <groupId>space.qu4nt.entanglementlib</groupId>
        <artifactId>entanglementlib</artifactId>
        <version>1.0.0</version>
    </dependency>
</dependencies>
```

#### Gradle Project

```kotlin
repositories {
    mavenCentral()
}

dependencies {
    implementaion("space.qu4nt.entanglementlib:entanglementlib:1.0.0")
    // or Groovy
    // implementaion 'space.qu4nt.entanglementlib:entanglementlib:1.0.0'
}
```

## TODO

This project is still lacking in many areas. EntanglementLib aims to clarify the following TODOs so that it can be used in financial and security infrastructure production in the future.

- [ ] **Provider Fluidity and Factory Optimization**
  - We need to modify it so that Java's default provider can be used according to the user's choice. And we need to optimize the factories provided in most classes, including the `InternalFactory` class.
- [ ] **Overall Design Pattern Optimization**
  - The current code has many dirty parts, enough to be called spaghetti code. We need to modify it to write pleasant code like my room.
- [ ] **JPMS Application**
  - Once secure encapsulation and consistent call (or usage) patterns are completed, we intend to manage encapsulated packages as modules through JPMS.
- [ ] **Remove `BouncyCastle` Dependency**
  - From the `1.1.0` release onwards, we intend to minimize `BC` dependency and eventually remove it. Currently, classical algorithms like AES, ARIA, and ChaCha20 still depend on `BC`. To solidify EntanglementLib's security philosophy, we have decided to perform all cryptographic operations in `entlib-native`.
- [ ] **`i18n` Update**
  - We missed a lot of multi-language support while developing the latest release. We need to modify it to support logging for each language according to configuration settings.

### Resolved

- [X] **Conflict between Java Module System (JPMS) and Reflection**
    - `KeyDestroyHelper` uses `Field.setAccessible(true)` to modify `private` fields in `BouncyCastle` internals or the Java standard library. Due to the strong encapsulation policy since Java 17, there is a very high probability that an `InaccessibleObjectException` will occur without the `--add-opens` JVM option at runtime.
    - You can bypass JPMS security warnings by adding the JVM option `--add-opens java.base/java.security=ALL-UNNAMED`.
        - **Resolution**: We didn't worry too much about solving this problem. Because we decided to use the `BC Lightweight API` from the `1.1.0` release. The first goal was to avoid some constraints of the existing JCA/JCE with low-level access. In other words, access via reflection is still indispensable. It means we might not be able to respond flexibly when generating keys or calling internal encryption engines. To solve these complex problems, we introduced the `entlib-native` native library and intend to focus on minimizing EntanglementLib's `BC` dependency.
- [X] **Performance vs. Security Trade-off**
    - We are performing defensive copies (deep copy) for all I/O. In server environments that process large data in gigabytes or require high throughput (Tick Per Second, TPS), frequent memory allocation and Garbage Collector load can cause performance degradation. Even looking at existing algorithm classes, binding data to instances is visible.
        - **Resolution**: We added the `entlib-native` native library and designed it so that all memory-related operations are handled on the `Rust` side. Now, on the `Java` side, we just need to erase sensitive data like byte arrays that are simply received. `Rust` will reliably handle memory operations in the background.
- [X] **Random Number and Nonce Management**
    - `ChaCha20Poly1305` uses `InternalFactory.getSafeRandom()` to generate the nonce value `Nonce`. If the `Nonce` is reused with the same key, the security of `ChaCha20Poly1305` completely collapses.
        - **Resolution**: This problem was also solved with the `entlib-native` native library. Now, a `ChaCha20`-based `CSPRNG` is created on the `Rust` side and used only on the `Rust` side. In other words, all cryptographic operations are now performed only by `Rust`!
- [X] **Writing Technical Specifications for Security Features**
    - **Resolution**: Important security-related features of EntanglementLib have been written in a [separate document](TECHNICAL.md).

## Contribution

In the early versions, EntanglementLib had really vague goals like 'BouncyCastle wrapper', 'half-hearted data erasure', etc. We spent quite a lot of time thinking deeply about this part and re-established EntanglementLib's unique goals.

Now, EntanglementLib is developed not just to provide PQC algorithms, but to be used as a competent tool that systematically monitors infrastructure security in the user's environment and finds solutions for the user. From the latest release, we will focus strongly on this belief.

Therefore... we need the power of many developers to complete the ultimate goal of EntanglementLib. Please leave feedback on the code at any time. It is a very, very big help to the Quant team!

## Alpha

Currently, EntanglementLib has released `1.1.0-Alpha` quite hastily to quickly reflect the accumulated updates. The stable version of this version is scheduled to be modified and reflected as the `1.1.0` official release. Since it is a one-person development, there is a problem that the speed is slow, but not much is left until all modifications.

## License

This project follows the `PolyForm Noncommercial License 1.0.0`. Please note that due to the simultaneous management of `entlib-native` within this project, the license is sometimes incorrectly reflected as `MIT`, but it still follows the `PolyForm` license. For more details on this license, please refer to the [LICENSE](LICENSE) file.

---

# Changelog

Changes can be found in the [CHANGE.md](CHANGE.md) document. This document will be added when the `1.1.0` release is published.