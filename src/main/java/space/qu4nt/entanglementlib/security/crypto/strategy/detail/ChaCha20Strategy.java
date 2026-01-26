/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalArgumentException;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoCipherIllegalIVStateException;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.security.crypto.CipherType;
import space.qu4nt.entanglementlib.security.crypto.strategy.StreamCipherStrategy;
import space.qu4nt.entanglementlib.util.io.EntFile;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.function.BiConsumer;

/// ChaCha20 스트림 암호 알고리즘 전략 클래스입니다.
///
/// ChaCha20은 AES의 대안으로 사용되는 고속 스트림 암호 알고리즘입니다.
/// BouncyCastle의 [ChaChaEngine]을 사용하여 암호화/복호화를 수행합니다.
///
/// 스트림 암호화는 [EntFile#byteBufferStreaming(Path, Path, int, int, BiConsumer)]
/// 메소드를 사용하여 대용량 파일을 효율적으로 처리할 수 있습니다.
/// IV(Nonce) 길이는 8바이트(64비트)를 사용합니다.
///
/// 키는 네이티브 메모리에서 관리되며, 사용 후 즉시 소거됩니다.
///
/// @author Q. T. Felix
/// @see AbstractStreamCipher
/// @see StreamCipherStrategy
/// @see CipherType#CHACHA20
/// @since 1.1.0
@Slf4j
public final class ChaCha20Strategy extends AbstractStreamCipher {

    /**
     * ChaCha20Strategy 생성자입니다.
     */
    ChaCha20Strategy() {
        super(CipherType.CHACHA20, new ChaChaEngine());
    }

    /**
     * ChaCha20Strategy 인스턴스를 생성하는 팩토리 메소드입니다.
     *
     * @return 새 {@link ChaCha20Strategy} 인스턴스
     */
    public static ChaCha20Strategy create() {
        return new ChaCha20Strategy();
    }

    @Override
    public int streamEncrypt(@NotNull SensitiveDataContainer keyContainer, @NotNull ByteBuffer inputBuffer, @NotNull ByteBuffer outputBuffer)
            throws EntLibSecureIllegalStateException, EntLibCryptoCipherIllegalIVStateException, EntLibSecureIllegalArgumentException {
        if (outputBuffer.remaining() < 8 + inputBuffer.remaining())
            throw new StackOverflowError("출력 버퍼가 너무 작습니다!");
        final SensitiveDataContainer input = new SensitiveDataContainer(inputBuffer.remaining());
        final SensitiveDataContainer output = encrypt(keyContainer, input, false);
        outputBuffer.put(output.getSegmentDataToByteBuffer());
        return Math.toIntExact(output.getMemorySegment().byteSize());
    }

    @Override
    public int streamDecrypt(@NotNull SensitiveDataContainer keyContainer, @NotNull ByteBuffer inputBuffer, @NotNull ByteBuffer outputBuffer)
            throws EntLibSecureIllegalStateException, EntLibCryptoCipherIllegalIVStateException, EntLibSecureIllegalArgumentException {
        if (inputBuffer.remaining() < 8)
            throw new StackOverflowError("입력 버퍼가 너무 작습니다!");
        final SensitiveDataContainer input = new SensitiveDataContainer(inputBuffer.remaining());
        final SensitiveDataContainer output = decrypt(keyContainer, input, false);
        outputBuffer.put(output.getSegmentDataToByteBuffer());
        return Math.toIntExact(output.getMemorySegment().byteSize());
    }

    @Override
    public SensitiveDataContainer encrypt(@NotNull SensitiveDataContainer keyContainer, final Object plain, boolean ivChaining)
            throws EntLibSecureIllegalStateException, EntLibCryptoCipherIllegalIVStateException, EntLibSecureIllegalArgumentException {
        iv.exportData();
        byte[] ivH = iv.getSegmentData();
        if (ivH == null)
            throw new EntLibCryptoCipherIllegalIVStateException("IV를 설정해야 합니다!");

        // 네이티브 메모리에서 키 바이트 배열 추출
        keyContainer.exportData();
        byte[] keyBytes = keyContainer.getSegmentData();
        if (keyBytes == null)
            throw new EntLibSecureIllegalStateException("네이티브 메모리에서 키 바이트 배열을 추출하지 못했습니다!");
        KeyParameter keyParam = new KeyParameter(keyBytes);

        ParametersWithIV params = new ParametersWithIV(keyParam, ivH);

        // 사용 후 힙에 복사된 키 바이트 즉시 소거
        KeyDestroyHelper.zeroing(keyBytes);

        byte[] plainWrap = plainCaster(plain);

        byte[] output = new byte[plainWrap.length];
        processStreamCipher(true, params, plainWrap, 0, plainWrap.length, output, 0);

        // 결과 반환: IV + CipherText
        if (ivChaining) {
            byte[] result = new byte[ivH.length + output.length];
            System.arraycopy(ivH, 0, result, 0, ivH.length);
            System.arraycopy(output, 0, result, ivH.length, output.length);
            KeyDestroyHelper.zeroing(output);
            KeyDestroyHelper.zeroing(ivH);
            return new SensitiveDataContainer(result, true);
        } else {
            KeyDestroyHelper.zeroing(ivH);
            return new SensitiveDataContainer(output, true);
        }
    }

    @Override
    public SensitiveDataContainer decrypt(@NotNull SensitiveDataContainer keyContainer, final SensitiveDataContainer ciphertext, boolean ivInference) throws EntLibSecureIllegalStateException, EntLibCryptoCipherIllegalIVStateException, EntLibSecureIllegalArgumentException {
        ciphertext.exportData();
        byte[] ciphertextH = ciphertext.getSegmentData();
        if (ciphertextH == null)
            throw new EntLibSecureIllegalStateException("네이티브 메모리에서 암호문 바이트 배열을 추출하지 못했습니다!");

        byte[] ivBytes;
        byte[] actualCiphertext;

        if (ivInference) {
            // 암호문에서 IV 추출
            if (ciphertextH.length < 8)
                throw new EntLibCryptoCipherIllegalIVStateException("IV를 포함하기에는 너무 짧은 암호문입니다!");

            ivBytes = new byte[8];
            System.arraycopy(ciphertextH, 0, ivBytes, 0, 8);

            actualCiphertext = new byte[ciphertextH.length - 8];
            System.arraycopy(ciphertextH, 8, actualCiphertext, 0, actualCiphertext.length);
        } else {
            // 외부에서 설정된 IV 사용
            iv.exportData();
            ivBytes = iv.getSegmentData();
            if (ivBytes == null)
                throw new EntLibCryptoCipherIllegalIVStateException("IV를 설정해야 합니다!");
            actualCiphertext = ciphertextH;
        }

        // 네이티브 메모리에서 키 바이트 배열 추출
        keyContainer.exportData();
        byte[] keyBytes = keyContainer.getSegmentData();
        if (keyBytes == null)
            throw new EntLibSecureIllegalStateException("네이티브 메모리에서 키 바이트 배열을 추출하지 못했습니다!");
        KeyParameter keyParam = new KeyParameter(keyBytes);

        // 사용 후 힙에 복사된 키 바이트 즉시 소거
        KeyDestroyHelper.zeroing(keyBytes);

        ParametersWithIV params = new ParametersWithIV(keyParam, ivBytes);
        byte[] output = new byte[actualCiphertext.length];
        processStreamCipher(false, params, actualCiphertext, 0, actualCiphertext.length, output, 0);

        return new SensitiveDataContainer(output, true);
    }

    /**
     * 알고리즘 이름을 반환하는 메소드입니다.
     *
     * @return 알고리즘 이름 "ChaCha20"
     */
    @Override
    public String getAlgorithmName() {
        return "ChaCha20";
    }
}
