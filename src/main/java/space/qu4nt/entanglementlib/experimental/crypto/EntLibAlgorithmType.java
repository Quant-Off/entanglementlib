/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto;

/**
 * 암호화 알고리즘의 공통 속성을 정의하는 인터페이스입니다.
 * <p>
 * 모든 암호화 알고리즘 타입({@link CipherType}, {@link SignatureType} 등)은
 * 이 인터페이스를 구현하여 알고리즘의 카테고리, 패밀리, 키 크기, PQC 여부 등의
 * 속성을 제공합니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see CipherType
 * @see SignatureType
 * @see EntLibCryptoCategory
 * @see CryptoFamily
 */
public interface EntLibAlgorithmType {

    /**
     * 이 알고리즘의 카테고리를 반환하는 메소드입니다.
     *
     * @return 알고리즘 카테고리 (암호화, 서명, 키 합의 등)
     */
    EntLibCryptoCategory getCategory();

    /**
     * 이 알고리즘이 속하는 패밀리를 반환하는 메소드입니다.
     *
     * @return 알고리즘 패밀리 (AES, RSA, ML-DSA 등)
     */
    CryptoFamily getFamily();

    /**
     * 이 알고리즘의 키 크기를 비트 단위로 반환하는 메소드입니다.
     *
     * @return 키 크기 (비트 단위)
     */
    int getKeySize();

    /**
     * 이 알고리즘이 PQC(Post-Quantum Cryptography) 알고리즘인지 여부를 반환하는 메소드입니다.
     *
     * @return PQC 알고리즘이면 {@code true}, 아니면 {@code false}
     */
    boolean isPQC();

}
