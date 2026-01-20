/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto;

/**
 * 암호화 알고리즘 패밀리(종류별 분류)를 정의하는 열거형 클래스입니다.
 * <p>
 * 각 암호화 알고리즘이 속하는 패밀리를 분류하며, 대칭 키 암호, 비대칭 키 암호,
 * 스트림 암호, PQC(Post-Quantum Cryptography) 알고리즘 등을 포함합니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see EntLibAlgorithmType
 */
public enum CryptoFamily {

    /** AES(Advanced Encryption Standard) 대칭 키 블록 암호 패밀리입니다. */
    AES,

    /** DES(Data Encryption Standard) 대칭 키 블록 암호 패밀리입니다. */
    DES,

    /** ChaCha 스트림 암호 패밀리입니다. */
    CHACHA,

    /** RSA 비대칭 키 암호 패밀리입니다. */
    RSA,

    /** SM2 중국 국가 표준 비대칭 키 암호 패밀리입니다. */
    SM2,

    /** ARIA 대칭 키 블록 암호 패밀리입니다. (대한민국 국가 표준) */
    ARIA,

    /** ML-DSA(Module-Lattice Digital Signature Algorithm) PQC 서명 알고리즘 패밀리입니다. */
    ML_DSA,

    /** ML-KEM(Module-Lattice Key Encapsulation Mechanism) PQC 키 캡슐화 알고리즘 패밀리입니다. */
    ML_KEM,

    /** SLH-DSA(Stateless Hash-based Digital Signature Algorithm) PQC 서명 알고리즘 패밀리입니다. */
    SLH_DSA

}
