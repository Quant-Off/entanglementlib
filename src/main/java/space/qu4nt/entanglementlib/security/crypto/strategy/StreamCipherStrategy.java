/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalArgumentException;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoCipherIllegalIVStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoCipherProcessException;
import space.qu4nt.entanglementlib.security.crypto.key.EntLibCryptoKey;

import java.nio.ByteBuffer;

/// 스트림 암호화 전략 인터페이스입니다.
///
/// ChaCha20 등의 스트림 암호 알고리즘을 위한 전략을 정의합니다.
/// 대용량 데이터를 스트리밍 방식으로 암호화/복호화할 때 사용됩니다.
///
/// @author Q. T. Felix
/// @see CipherStrategy
/// @since 1.1.0
public interface StreamCipherStrategy extends CipherStrategy {

    /**
     * 입력 버퍼의 데이터를 스트리밍 방식으로 암호화하여 출력 버퍼에 쓰는 메소드입니다.
     *
     * @param keyContainer          암호화에 사용할 키
     * @param inputBuffer  암호화할 데이터가 담긴 입력 버퍼
     * @param outputBuffer 암호화된 데이터를 쓸 출력 버퍼
     * @return 처리된 바이트 수
     */
    int streamEncrypt(@NotNull SensitiveDataContainer keyContainer, final @NotNull ByteBuffer inputBuffer, final @NotNull ByteBuffer outputBuffer) throws EntLibSecureIllegalStateException, EntLibCryptoCipherIllegalIVStateException, EntLibSecureIllegalArgumentException;

    /**
     * 입력 버퍼의 데이터를 스트리밍 방식으로 복호화하여 출력 버퍼에 쓰는 메소드입니다.
     *
     * @param keyContainer          복호화에 사용할 키
     * @param inputBuffer  복호화할 데이터가 담긴 입력 버퍼
     * @param outputBuffer 복호화된 데이터를 쓸 출력 버퍼
     * @return 처리된 바이트 수
     */
    int streamDecrypt(@NotNull SensitiveDataContainer keyContainer, final @NotNull ByteBuffer inputBuffer, final @NotNull ByteBuffer outputBuffer) throws EntLibSecureIllegalStateException, EntLibCryptoCipherProcessException, EntLibSecureIllegalArgumentException;
}
