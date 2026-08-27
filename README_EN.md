# EntanglementLib

[![Version](https://img.shields.io/badge/version-2.0.0-blue?style=for-the-badge)](https://github.com/Quant-Off/entanglementlib)
[![README-Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)
[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial%20License%201.0.0-green?style=for-the-badge)](LICENSE)
[![Language](https://img.shields.io/badge/language-Java-orange?style=for-the-badge)](https://github.com/Quant-Off/entanglementlib)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/9utg4hp3m8)

![EntanglementLib](entanglementlib-logo.png)

EntanglementLib is a library designed to process all security operations safely and quickly. Through its linked [Rust native layer](https://github.com/Quant-Off/entlib-native), it provides classical and post-quantum cryptography (PQC) technologies, along with a forward-looking TLS protocol built on top.

## Technology

EntanglementLib performs all security operations through **Rust-based native code**. The native layer fundamentally prevents all security vulnerabilities that can arise from the garbage collector's cleanup mechanism in `heap` memory allocation. It accepts sensitive data from Java as `off-heap` memory, performs operations, and immediately secures the data at those pointers through caller/callee patterns.

When Java interacts with native code, it does not use the JNI (Java Native Interface). The core technology is the Linker and FFM API (Foreign Function & Memory API), advanced native calling capabilities based on [JEP 389](https://openjdk.org/jeps/389) and [JEP 454](https://openjdk.org/jeps/454) improvements. On the native side, encapsulated logic integrates via FFI (Foreign Function Interface).

> [!TIP]
> If you're curious about the background and overview of the native layer, see [here](https://qu4nt.space/projects/entlib-native).
>
> Or if you're curious about the background of EntanglementLib, see [here](https://qu4nt.space/projects/entanglementlib).

User data within this library is never managed as byte arrays (`byte[]`) or char arrays (`char[]`). Those types are written to `heap` memory, giving the GC control over them. Instead of such primitive usage, use the `SensitiveDataContainer` object. This object takes ownership of sensitive data, safely passes it to native code, and handles processing securely and efficiently. More specifically, the object acquires resources at instantiation and releases them upon calling `close()`, similar to [Rust's RAII (Resource Acquisition Is Initialization) pattern](https://doc.rust-lang.org/rust-by-example/scope/raii.html).

### Multi-module

EntanglementLib is a multi-module project. Each module's responsibilities are split across utility features including operations, practical annotations, and various convenience tools. The annotation and core modules are used centrally from the security modules, but the security modules are never used from other modules.

| Module                       | Function                                                               |
|------------------------------|------------------------------------------------------------------------|
| `security`                   | The core security module. Contains logic for interacting with native code and provides various security features integrated via FFI. |
| `core`                       | Provides utility functions for managing exceptions, internationalization, async operations, chunked work, strings, and data structures. |
| `annotations`                | Contains annotations for simplified code design and reduced complexity in understanding user code. |
| `internal-shared-server`     | Includes features for forming and managing infrastructure in closed environments. |

## Warnings and Crypto Provider Configuration

**Cryptographic verification of the security features (Rust) called from EntanglementLib (Java) to native has not been sufficiently completed.** Team Quant is striving to achieve full verification of `entlib-native`.

> [!IMPORTANT]
> Verifying crypto modules takes considerable time. Therefore, please use the `entlib-native` provider **"for experimental (research) purposes only."**

You can configure the 'security feature provider' implemented in the Rust layer to use an 'already verified secure provider' instead of `entlib-native`.

### Provider Configuration

All security features used across the FFI boundary (digests, encodings, AEAD, random number generation) can select their backend via `CryptoProviderConfig`. Options include:

- `CryptoBackend#JDK_VERIFIED` — Verified backend using standard JDK JCA (`MessageDigest`, `Cipher`, `SecureRandom`, `java.util.Base64`, `HexFormat`) (**default**)
- `CryptoBackend#ENTLIB_NATIVE` — `entlib-native` FFI backend (unverified, experimental)
- User-supplied verified provider instance injection (e.g., HSM, PKCS#11, internal verification library)

The default is **verified JDK backend**. Therefore, without any additional configuration, initialization uses the verified provider instead of unverified native code.

```java
// 1) Default (full verified JDK backend)
EntanglementLibSecurityFacade.initialize(
        EntanglementLibSecurityConfig.create(null, HeuristicArenaFactory.ArenaMode.AUTO));

// 2) Global + per-feature mix + external JCA provider (BouncyCastle, etc.) + custom provider injection
CryptoProviderConfig providers = CryptoProviderConfig.builder()
        .useVerifiedProviders()            // Set global default to verified JDK
        .aead(CryptoBackend.ENTLIB_NATIVE) // AEAD only via native (experimental)
        .jcaProviderName("BC")             // JCA provider name for verified backends
        .random(myVerifiedRandomProvider)  // RNG via user-defined verified provider
        .build();

EntanglementLibSecurityFacade.initialize(
        EntanglementLibSecurityConfig.create(
                nativeSpecContext, HeuristicArenaFactory.ArenaMode.AUTO, providers));

// 3) Full entlib-native (experimental)
EntanglementLibSecurityConfig.create(nativeSpecContext, null, CryptoProviderConfig.nativeDefaults());
```

> [!TIP]
> When all features resolve to verified (or custom) providers (`requiresNative() == false`), EntanglementLib will **not load** unverified native binaries. You can use only verified security operations without deploying native binaries in closed environments.

> [!NOTE]
> **The verified JDK backend briefly exposes sensitive data on the JVM `heap` during computation due to JCA characteristics.** The library immediately zeroes temporary `byte[]` instances it uses, but this is an intentional trade-off for verified correctness. Additionally, **SHAKE (XOF) variable-length output and quantum network randomness are not supported in the verified backend** as they have no JDK standard equivalent (native or XOF-capable providers are required).

## Air-gapped Shared Server

The `internal-shared-server` (ISS) module is a secure shared server that multiple internal nodes connect to within an air-gapped network. It excludes the public internet CA trust chain, mutually authenticates both sides with a pre-shared key (PSK), and protects every record with `ChaCha20-Poly1305`. Since it operates using only the verified JDK provider, it can be used without deploying native binaries. It is controlled through two paths: the code-level embedded API (`ISSServer` / `ISSClient`) and the CLI.

> [!NOTE]
> Because it does not use DH/KEM for key establishment, it does not provide forward secrecy (PFS). If the PSK is exposed, past and future traffic is at risk, so operate it with a strong PSK and periodic rotation. By default the server binds only to loopback (127.0.0.1); LAN exposure requires explicit opt-in.

### Preparing the Executable

Generating an application distribution produces a launch script.

```bash
./gradlew :internal-shared-server:installDist
# Output location
# internal-shared-server/build/install/internal-shared-server/bin/internal-shared-server

# Register an alias for convenience (optional)
alias iss="$(pwd)/internal-shared-server/build/install/internal-shared-server/bin/internal-shared-server"
```

Or you can run it directly with Gradle.

```bash
./gradlew :internal-shared-server:run --args="--help"
```

### CLI Usage

```text
iss serve   --port N [--bind 127.0.0.1] (--psk-file F | --psk-env VAR)
            [--max-conn 64] [--allow-nonloopback] [--allow-peer IP]...
iss ping    --port N [--host 127.0.0.1] (--psk-file F | --psk-env VAR)
iss put     --port N [--host H] (--psk-file F | --psk-env VAR)
            --key K (--value V | --value-file F | --stdin)
iss get     --port N [--host H] (--psk-file F | --psk-env VAR) --key K [--out FILE]
iss del     --port N [--host H] (--psk-file F | --psk-env VAR) --key K
iss list    --port N [--host H] (--psk-file F | --psk-env VAR)
iss status  --port N [--host H] (--psk-file F | --psk-env VAR)
iss gen-psk [--bytes 32] [--out FILE]
iss --help | --version
```

| Command   | Description                                                                 |
|-----------|----------------------------------------------------------------------------|
| `serve`   | Bind the server and start accepting connections (exit with Ctrl-C)         |
| `ping`    | Verify the server response after the handshake                             |
| `put`     | Store a value under a key (value from argument, file, or stdin)            |
| `get`     | Retrieve a key's value (saves to file with `--out`, else stdout; 1 if absent) |
| `del`     | Delete a key                                                               |
| `list`    | Print the list of stored keys                                             |
| `status`  | Query the server status                                                    |
| `gen-psk` | Generate a PSK from a secure RNG (prints hex to stdout if no `--out`)      |

> [!IMPORTANT]
> The PSK is not accepted as a plaintext command-line argument (to prevent exposure in the process list). It is supplied only via a raw-byte key file (`--psk-file`) or a hex environment variable (`--psk-env`), and a minimum of 32 bytes is required. Logs go to standard error, while command result data is separated to standard output.

### Quick Start

```bash
# 1) Generate a PSK (raw 32-byte key file, saved with owner-only permissions)
iss gen-psk --out infra.psk

# 2) Start the server (loopback by default)
iss serve --port 8443 --psk-file infra.psk

# 3) Run client commands from another terminal
iss ping   --port 8443 --psk-file infra.psk
iss put    --port 8443 --psk-file infra.psk --key greeting --value "Hello"
iss get    --port 8443 --psk-file infra.psk --key greeting
iss list   --port 8443 --psk-file infra.psk
iss status --port 8443 --psk-file infra.psk
iss del    --port 8443 --psk-file infra.psk --key greeting

# Pass the PSK via an environment variable (hex)
export ISS_PSK=$(iss gen-psk)
iss ping --port 8443 --psk-env ISS_PSK
```

## Contributing

We are ready to actively receive your feedback. EntanglementLib is developed not merely to provide PQC algorithms, but to serve as a capable tool that systematically monitors infrastructure security in user environments and provides solutions. Recent releases put a strong emphasis on this belief.

## TODO

EntanglementLib aims to clear the following TODOs so it can be used in financial and security infrastructure production in the future.

- [ ] Local-hosted web development for useful usage in air-gapped environments
  - ISS is currently controlled only through the CLI and the embedded API (`ISSServer` / `ISSClient`). A web-based management console does not exist yet.
- [ ] Additional TLS communication logic
  - The ISS PSK mutual-authentication + ChaCha20-Poly1305 secure channel has been fully implemented.
  - An `ExternalTLS` facade skeleton was added to the `security` module, but the handshake remains inactive (a stub) until ML-KEM key establishment, ChaCha20-Poly1305 record AEAD, and RNG nonce generation are exposed in the native FFI.
- [ ] Preparation and execution of comprehensive verification tasks
  - A crypto provider SPI (`CryptoProviderConfig`) was added so you can choose a verified JDK provider (or a custom provider) instead of unverified native code. Cryptographic verification of `entlib-native` itself is still ongoing.
- [x] Custom exception optimization
  - An exception hierarchy split into checked/unchecked and core/security layers, along with an i18n-integrated `ExceptionLogger`, has been established.
- [ ] JPMS application (package modularization even within multi-module)
  - Once secure encapsulation and consistent call (or usage) patterns are established, we plan to manage encapsulated packages as modules via JPMS.
- [ ] Minimize external dependencies
  - Starting from release `1.1.0`, we no longer depend on `BouncyCastle`, and the `Lombok` dependency has also been removed. Some useful dependency-provided tools needed for current code still remain, but these will also ultimately be minimized.
- [ ] `i18n` updates
  - The `core` module's `EntanglementLibCoreI18n` and the `en_US` / `ko_KR` message bundles are in place. However, the integration that automatically applies per-language logging based on configuration settings still needs further refinement.

## License

This project follows the `PolyForm Noncommercial License 1.0.0`. Due to co-managing `entlib-native` within this project, the license may occasionally be incorrectly reflected as `MIT` — please note that it still follows the `PolyForm` license. For more details on this license, see the [LICENSE](LICENSE) file.

---

# Changelog

You can find the changelog in the [CHANGE.md](CHANGE.md) document. This will be added starting with the `1.1.0` release.
