# Security Policy

> [Korean SECURITY](SECURITY.md)

EntanglementLib holds "military-grade security" and "Anti-Data Remanence" as its core philosophies. We take your security vulnerability reports very seriously, and any discovered issues are treated with the highest priority.

## Supported Versions

Currently, EntanglementLib is in the **Alpha** stage. Security updates are applied first to the latest development version.

| Version       | Supported          | Remarks                                        |
|:--------------|:-------------------|:-----------------------------------------------|
| 1.1.x (Alpha) | :white_check_mark: | Currently under active development and support |
| < 1.1.0       | :x:                | End of support                                 |

## Reporting a Vulnerability

If you discover a security vulnerability or a sensitive data remanence issue in EntanglementLib, **please DO NOT post it publicly on GitHub Issues!** Instead, we ask that you report it privately following the procedure below.

### How to Report

1. Contact me directly via email at [qtfelix@qu4nt.space](mailto:qtfelix@qu4nt.space).
2. Please include `[SECURITY] EntanglementLib Vulnerability Report [GITHUB USERNAME]` in the email subject.
3. If possible, please include the following information:
    * Type of vulnerability (timing issues, key remanence in memory dumps, FFI boundary check bypass, PQC algorithm implementation errors, etc.)
    * Steps to reproduce (PoC code or step-by-step description)
    * Affected versions and environment (OS, Java version, etc.)

> [!NOTE]
> If a PGP key is required for secure communication, please check the `KEYS` file in the repository or request it.

### Handling Process

Reported vulnerabilities are processed according to the following procedure:

1. **Acknowledgment:** We will send an acknowledgment email to the reporter within 48 hours.
2. **Analysis and Verification:** The Quant team will closely analyze the impact and reproducibility of the vulnerability internally.
3. **Patch Development:** Once the issue is confirmed, we will develop a hotfix for `entlib-native` or `entanglementlib`.
4. **Disclosure and Deployment:** After the patch is completed and released, we will disclose the vulnerability information at an appropriate time in consultation with the reporter.

## Security Focus Areas

We particularly welcome reports on the following areas:

* **Memory Safety Violations:** Cases where sensitive data is found in heap dumps or memory snapshots even after calling `SensitiveDataContainer#close()`.
* **FFI Boundary Check Failures:** Cases that can cause invalid pointer access or crashes when calling `entlib-native`.
* **Encryption Implementation Flaws:** PQC algorithm behaviors that differ from NIST standards (FIPS 203, 204, 205) or `nonce` reuse issues in classical algorithms.

## Out of Scope

The following items are generally excluded from security vulnerability reports, but may be reviewed if severe:

* Issues caused by user configuration errors (e.g., insufficient permission settings for the `ENTLIB_NATIVE_BIN` path).
* Vulnerabilities in already public external libraries themselves (however, issues caused by misuse in EntanglementLib are included).
* Social engineering or physical attacks.

## Acknowledgments

If the issue is confirmed as a vulnerability, we will publish a security advisory and acknowledge your contribution. If you wish, we can also list your name and contact information in our acknowledgments.

We would like to express our gratitude in advance to all security researchers and developers who contribute to strengthening the security of EntanglementLib.