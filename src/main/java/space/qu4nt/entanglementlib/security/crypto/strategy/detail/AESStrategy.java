/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalArgumentException;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoCipherIllegalIVStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoCipherProcessException;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.security.crypto.CipherType;
import space.qu4nt.entanglementlib.security.crypto.Mode;

import java.util.Arrays;

/// AES(Advanced Encryption Standard) 블록 암호 알고리즘 전략 클래스입니다.
///
/// BouncyCastle의 [AESEngine]을 사용하여 AES 암호화/복호화를 수행합니다.
/// AES-128, AES-192, AES-256 키 길이를 지원하며, 다양한 운영 모드(CBC, GCM, CTR 등)와
/// 패딩 방식을 설정할 수 있습니다.
///
/// 키는 네이티브 메모리에서 관리되며, 사용 후 즉시 소거됩니다.
///
/// @author Q. T. Felix
/// @see AbstractBlockCipher
/// @see CipherType#AES_128
/// @see CipherType#AES_192
/// @see CipherType#AES_256
/// @since 1.1.0
@Slf4j
public final class AESStrategy extends AbstractBlockCipher {

    /**
     * AESStrategy 생성자입니다.
     *
     * @param base AES 암호화 타입 ({@link CipherType#AES_128}, {@link CipherType#AES_192}, {@link CipherType#AES_256})
     */
    AESStrategy(@NotNull CipherType base) {
        super(base, AESEngine.newInstance());
    }

    /**
     * AESStrategy 인스턴스를 생성하는 팩토리 메소드입니다.
     *
     * @param base AES 암호화 타입 ({@link CipherType#AES_128}, {@link CipherType#AES_192}, {@link CipherType#AES_256})
     * @return 새 {@link AESStrategy} 인스턴스
     */
    @ApiStatus.Internal
    public static AESStrategy create(@NotNull CipherType base) {
        return new AESStrategy(base);
    }

    /**
     * 평문을 AES 알고리즘으로 암호화하는 메소드입니다.
     * <p>
     * ECB 모드를 제외한 모든 모드에서 IV(초기화 벡터)가 자동으로 생성되며,
     * 결과는 {@code IV + CipherText} 형식으로 반환됩니다.
     * AEAD 모드(GCM, CCM)에서는 12바이트 IV를, 그 외 모드에서는 16바이트 IV를 사용합니다.
     *
     * @param keyContainer 암호화에 사용할 키
     * @param plain        암호화할 평문 바이트 배열
     * @return 암호화된 바이트 배열 (IV + CipherText)
     * @throws IllegalStateException 암호화 실패 시
     */
    @Override
    public SensitiveDataContainer encrypt(@NotNull SensitiveDataContainer keyContainer, final Object plain, boolean ivChaining)
            throws EntLibSecureIllegalStateException, EntLibCryptoCipherProcessException {
        boolean isAead = mode.isAead();
        CipherParameters params;

        // 네이티브 메모리에서 키 바이트 배열 추출
        keyContainer.exportData();
        byte[] keyBytes = keyContainer.getSegmentData();
        if (keyBytes == null)
            throw new EntLibSecureIllegalStateException("네이티브 메모리에서 키 바이트 배열을 추출하지 못했습니다!");
        KeyParameter keyParam = new KeyParameter(keyBytes);

        // 사용 후 힙에 복사된 키 바이트 즉시 소거
        KeyDestroyHelper.zeroing(keyBytes);

        // iv 호출
        iv.exportData();
        byte[] ivH = iv.getSegmentData();
        if (ivH == null)
            throw new EntLibSecureIllegalStateException("IV를 생성해야 합니다!");

        if (mode != Mode.ECB) {
            if (isAead) {
                // AEAD 모드는 AEADParameters 사용 (macSize = 128 bits)
                params = new AEADParameters(keyParam, 128, ivH);
            } else {
                params = new ParametersWithIV(keyParam, ivH);
            }
        } else {
            params = keyParam;
        }

        byte[] output = processCipher(true, params, plain);

        if (mode != Mode.ECB && ivChaining) {
            // IV + CipherText
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

    /**
     * 암호문을 AES 알고리즘으로 복호화하는 메소드입니다.
     * <p>
     * 입력된 암호문에서 IV를 추출하여 복호화를 수행합니다.
     * AEAD 모드에서는 12바이트, 그 외 모드에서는 16바이트의 IV를 추출합니다.
     *
     * @param keyContainer 복호화에 사용할 키
     * @param ciphertext   복호화할 암호문 바이트 배열 (IV + CipherText)
     * @return 복호화된 평문 바이트 배열
     * @throws IllegalStateException    복호화 실패 시
     * @throws IllegalArgumentException 암호문이 IV보다 짧은 경우
     */
    @Override
    public SensitiveDataContainer decrypt(@NotNull SensitiveDataContainer keyContainer, final SensitiveDataContainer ciphertext, boolean ivInference)
            throws EntLibSecureIllegalStateException, EntLibCryptoCipherProcessException {
        boolean isAead = mode.isAead();
        byte[] actualCiphertext;
        CipherParameters params;

        // 네이티브 메모리에서 키 바이트 배열 추출
        keyContainer.exportData();
        byte[] keyBytes = keyContainer.getSegmentData();
        if (keyBytes == null)
            throw new EntLibSecureIllegalStateException("네이티브 메모리에서 키 바이트 배열을 추출하지 못했습니다!");
        KeyParameter keyParam = new KeyParameter(keyBytes);

        // 사용 후 힙에 복사된 키 바이트 즉시 소거
        KeyDestroyHelper.zeroing(keyBytes);

        ciphertext.exportData();
        byte[] ciphertextH = ciphertext.getSegmentData();
        if (ciphertextH == null)
            throw new EntLibSecureIllegalStateException("네이티브 메모리에서 암호문 바이트 배열을 추출하지 못했습니다!");

        if (mode != Mode.ECB) {
            byte[] ivBytes;

            if (ivInference) {
                // 암호문에서 IV 추출
                int ivLength = isAead ? 12 : 16;
                if (ciphertextH.length < ivLength)
                    throw new EntLibCryptoCipherIllegalIVStateException("IV를 포함하기에는 너무 짧은 암호문입니다!");

                ivBytes = Arrays.copyOfRange(ciphertextH, 0, ivLength);
                actualCiphertext = Arrays.copyOfRange(ciphertextH, ivLength, ciphertextH.length);
            } else {
                // 외부에서 설정된 IV 사용
                iv.exportData();
                ivBytes = iv.getSegmentData();
                if (ivBytes == null)
                    throw new EntLibCryptoCipherIllegalIVStateException("IV를 설정해야 합니다!");
                actualCiphertext = ciphertextH;
            }

            if (isAead) {
                params = new AEADParameters(keyParam, 128, ivBytes);
            } else {
                params = new ParametersWithIV(keyParam, ivBytes);
            }
        } else {
            actualCiphertext = ciphertextH;
            params = keyParam;
        }

        return new SensitiveDataContainer(processCipher(false, params, actualCiphertext), true);
    }

    /**
     * 알고리즘 이름을 반환하는 메소드입니다.
     *
     * @return 알고리즘 이름 "AES"
     */
    @Override
    public String getAlgorithmName() {
        return "AES";
    }
}
