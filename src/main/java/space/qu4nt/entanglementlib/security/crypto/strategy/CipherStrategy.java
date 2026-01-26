/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalArgumentException;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoCipherProcessException;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.ChaCha20Strategy;

import java.util.Arrays;

/// 암호화/복호화 연산을 수행하는 전략 인터페이스입니다.
///
/// 블록 암호([BlockCipherStrategy]), 스트림 암호([StreamCipherStrategy]),
/// AEAD 암호([AEADCipherStrategy]) 등이 이 인터페이스를 확장합니다.
///
/// @author Q. T. Felix
/// @see BlockCipherStrategy
/// @see StreamCipherStrategy
/// @see AEADCipherStrategy
/// @since 1.1.0
public interface CipherStrategy extends EntLibCryptoStrategy {

    void iv(Object raw) throws EntLibSecureIllegalArgumentException;

    /// 평문을 암호화하는 메소드입니다.
    ///
    /// 평문 객체의 경우, `byte[]`, [SensitiveDataContainer] 또는
    /// [java.nio.ByteBuffer] 타입을 전달해야 합니다. 이 메소드를
    /// 수행하기 전, 입력값의 유효성을 검사하는 로직을 수행하세요.
    ///
    /// TLS 1.3 과 같은 통신 프로토콜에서 사용하는 경우, `ivChaining`
    /// 논리 값을 `false`로 전달하여 결과에 `iv`값을 포함하지 않도록
    /// 할 수 있습니다.
    ///
    /// [ChaCha20Strategy] 에서 사용하는 경우, `ivChaining`
    /// 매개변수의 값을 전달하는
    ///
    /// @param keyContainer 암호화에 사용할 키 컨테이너
    /// @param plain        암호화할 평문 객체
    /// @param ivChaining   `true` 시 결과에 IV값 연결
    /// @return 암호화된 암호문 컨테이너
    SensitiveDataContainer encrypt(@NotNull SensitiveDataContainer keyContainer, final Object plain, boolean ivChaining) throws EntLibSecureIllegalStateException, EntLibCryptoCipherProcessException, EntLibSecureIllegalArgumentException;

    /// 암호문을 복호화하는 메소드입니다.
    ///
    /// @param keyContainer 복호화에 사용할 키 컨테이너
    /// @param ciphertext   복호화할 암호문 바이트 배열
    /// @param ivInference  true 시 암호문에 IV가 존재한다고 예상
    /// @return 복호화된 평문 바이트 배열
    SensitiveDataContainer decrypt(@NotNull SensitiveDataContainer keyContainer, final SensitiveDataContainer ciphertext, boolean ivInference) throws EntLibSecureIllegalStateException, EntLibCryptoCipherProcessException, EntLibSecureIllegalArgumentException;

    /// TLS 1.3 방식의 Nonce 생성 헬퍼 메소드입니다.
    ///
    /// BaseIV(12bytes) XOR Sequence(8bytes)
    static SensitiveDataContainer calculateNonce(byte[] baseIV, long sequence) {
        byte[] nonce = Arrays.copyOf(baseIV, 12); // 12바이트 GCM IV 길이

        // 시퀀스 번호를 뒤에서부터 XOR (Big Endian 처리)
        for (int i = 0; i < 8; i++)
            nonce[11 - i] ^= (byte) (sequence >> (i * 8));

        return new SensitiveDataContainer(nonce, true);
    }
}
