/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto;

import java.util.Locale;
import java.util.Objects;

/// 암호화 알고리즘의 공통 속성을 정의하는 인터페이스입니다.
///
/// 모든 암호화 알고리즘 타입([CipherType], [SignatureType] 등)은
/// 이 인터페이스를 구현하여 알고리즘의 카테고리, 패밀리, 키 크기, PQC 여부 등의
/// 속성을 제공합니다.
///
/// @author Q. T. Felix
/// @see CipherType
/// @see SignatureType
/// @see EntLibCryptoCategory
/// @see CryptoFamily
/// @since 1.1.0
public interface EntLibAlgorithmType {

    // todo: 레지스트리에서 원활한 타입 추론을 위해 이 인터페이스를 클래스로 변경하는 등 크게 개편

    String getName();

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

    /// 이 알고리즘의 사이즈 디테일을 반환합니다.
    ///
    /// @return 정의된 [ParameterSizeDetail] 객체
    ParameterSizeDetail getParameterSizeDetail();

    /**
     * 이 알고리즘이 PQC(Post-Quantum Cryptography) 알고리즘인지 여부를 반환하는 메소드입니다.
     *
     * @return PQC 알고리즘이면 {@code true}, 아니면 {@code false}
     */
    boolean isPQC();

    default String getContextIdentifier() {
        return Objects.requireNonNull(getName()).toLowerCase(Locale.ROOT).replace('-', '_').trim();
    }
}
