# EntanglementLib

[![Version](https://img.shields.io/badge/version-1.1.0%20Alpha-blue?style=for-the-badge)](https://github.com/Quant-Off/entanglementlib)
[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial%20License%201.0.0-green?style=for-the-badge)](LICENSE)
[![Language](https://img.shields.io/badge/language-Java-orange?style=for-the-badge)](https://github.com/Quant-Off/entanglementlib)

![EntanglementLib](entanglementlib-logo.png)

EntanglementLib is a military-grade security library designed to process all security operations safely and quickly. It provides classical and Post-Quantum Cryptography (PQC) technologies, and offers a future-oriented TLS protocol using them.

It aims to provide the highest level of security and system stability in response to the evolving digital threat environment.

> [Korean README](README.md)

## Core Philosophy

All designs of EntanglementLib prioritize security for 'military security' and 'establishing secure infrastructure in financial and large enterprise environments'. EntanglementLib is implemented to fundamentally prevent potential security vulnerabilities and ensure data integrity. The second core value is stability. To ensure predictable and consistent performance, Rust native operations are applied to maximize memory efficiency very safely, and a systematic error (or exception) handling mechanism is equipped.

## Technology

EntanglementLib performs all security operations through [Rust-based native](https://github.com/Quant-Off/entlib-native). Native destroys all security weaknesses that can be triggered in the cleaning mechanism of the Garbage Collector (GC) due to `heap` memory allocation. It receives sensitive data from the Java side as `off-heap` to perform tasks, and immediately and safely erases the data of the pointer through the caller or callee pattern.

When interacting with Native from the Java side, simply JNI (Java Native Interface) functions are not used. The core technology is the Linker, FFM API (Foreign Function & Memory API), which is an advanced native call function based on [JEP 389](https://openjdk.org/jeps/389) and [JEP 454](https://openjdk.org/jeps/454) improvements, and on the Native side, it is linked via FFI (Foreign Function Interface) through encapsulated logic.

> [!TIP]
> If you are curious about the background and overview of Native, please refer to [here](https://qu4nt.space/projects/entlib-native).
>
> Or if you are curious about the background of EntanglementLib, please refer to [here](https://qu4nt.space/projects/entanglementlib).

Within this library, user data is not managed as byte arrays (`byte[]`) or character arrays (`char[]`). These types give initiative to `heap` memory, and furthermore to GC. Instead of this primitive use, you can use the `SensitiveDataContainer` object. This object takes over the ownership of sensitive data and passes it safely to Native to help process tasks safely and efficiently. More specifically, this object acquires resources at the time of instantiation and releases resources at the time of `close()` call, similar to [Rust's RAII (Resource Acquisition Is Initialization) pattern](https://doc.rust-lang.org/rust-by-example/scope/raii.html). This concept may be quite unique in Java.

## Multi-module

EntanglementLib is now a multi-module project. The role of each module is divided into utilities including tasks and practical annotations, security, and various convenience tools. Annotation and core modules are essentially used in security modules, but security modules are never used in other modules.

| Module          | Function                                                                                                                                  |
|-----------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| `security`      | Core security module. Provides logic for interaction with Native and various security functions linked via FFI.                           |
| `core`          | Provides utility functions managing exceptions, internationalization and asynchronous, chunk operations, strings, and data structures.    |
| `annotations`   | Includes annotations for easy code design and improving user's code understanding complexity.                                             |


## Technical Specification

Detailed technical specifications for EntanglementLib are being written.

## Benchmarking Records

We are performing bridge benchmarking for various operations such as nanosecond delays occurring when calling Rust native functions using FFM API in EntanglementLib. This work is directly related to performance and security, and plays an important role in creating optimal code.

Many benchmarking tasks are scheduled in this alpha version. We plan to proceed with this work through JMH (Java Microbenchmark Harness), and we will organize it in a new document as soon as it is completed.

## Contribution

This project is currently `Alpha` version, and is still lacking a lot. We are already ready to actively receive your feedback. EntanglementLib is developed not only to provide PQC algorithms, but also to be used as a competent tool that systematically monitors infrastructure security in the user environment and finds solutions for users. From the latest release, we will focus strongly on this belief.

## TODO

EntanglementLib wants to clarify the following TODOs so that it can be used in financial and security infrastructure production in the future.

- [ ] Add TLS communication logic
- [ ] Prepare and perform complex verification tasks
- [ ] Custom Exception Optimization
- [ ] Apply JPMS
    - Once secure encapsulation and consistent call (or usage) patterns are completed, we intend to manage encapsulated packages as modules through JPMS.
- [ ] Minimize external dependencies
    - Now, from the `1.1.0` release, we have minimized `BouncyCastle` dependencies and finally succeeded in removing them. Dependencies that provide some useful tools needed for current code writing still remain, but these will also be minimized eventually.
- [ ] Update `i18n`
    - While performing the latest release development, we missed a lot of multilingual support. We need to modify it to support logging for each language according to configuration settings.

### Resolved

- [X] Conflict between Java Module System (JPMS) and Reflection
    - In `KeyDestroyHelper`, `Field.setAccessible(true)` is used to modify `private` fields inside `BouncyCastle` or Java standard libraries. Due to the strong encapsulation policy since Java 17, there is a very high probability that `InaccessibleObjectException` will occur without the `--add-opens` JVM option at runtime.
    - You can bypass JPMS security warnings by adding the JVM option `--add-opens java.base/java.security=ALL-UNNAMED`.
        - **Resolution**: We didn't worry too much to solve this problem. Because we decided to use `BC Lightweight API` from the `1.1.0` release. The first goal was to avoid some restrictions of existing JCA/JCE with low-level access. In other words, access through reflection is still inevitable. It means that we may not be able to respond flexibly when generating keys or calling internal encryption engines. To solve these complex problems, we introduced the `entlib-native` native library, and we intend to focus on minimizing `BC` dependencies of EntanglementLib.
- [X] Performance vs Security Trade-off
    - Defensive copy (deep copy) is performed for all inputs and outputs. In server environments that process large data in gigabytes or require high throughput (Tick Per Second, TPS), frequent memory allocation and garbage collector load can cause performance degradation. Just looking at existing algorithm classes, you can see data binding to instances.
        - **Resolution**: By adding the `entlib-native` native library, we designed all memory-related operations to be processed on the `Rust` side. Now, on the `Java` side, we simply need to erase sensitive data such as byte arrays received purely. `Rust` will reliably take care of memory operations in the back.
- [X] Random Number and Nonce Management
    - In `ChaCha20Poly1305`, `InternalFactory.getSafeRandom()` is used to generate nonce value `Nonce`. If `Nonce` is reused with the same key, the security of `ChaCha20Poly1305` collapses completely.
        - **Resolution**: This problem was also solved with the `entlib-native` native library. Now, `ChaCha20`-based `CSPRNG` is created on the `Rust` side, and used only on the `Rust` side. In other words, all cryptographic operations are now performed only by `Rust`!
- [X] Writing Technical Specifications for Security Functions
    - **Resolution**: Important security-related functions of EntanglementLib have been written in a [separate document](TECHNICAL.md).

## License

This project follows `PolyForm Noncommercial License 1.0.0`. Please note that although the license is sometimes incorrectly reflected as `MIT` due to simultaneous management of `entlib-native` within this project, it still follows the `PolyForm` license. For more details on this license, please refer to the [LICENSE](LICENSE) file.

---

# Changes

Changes can be found in the [CHANGE.md](CHANGE.md) document. This document will be added when the `1.1.0` release is published.