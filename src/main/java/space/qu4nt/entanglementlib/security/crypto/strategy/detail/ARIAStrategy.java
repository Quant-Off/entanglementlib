/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoCipherIllegalIVStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoCipherProcessException;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.security.crypto.CipherType;
import space.qu4nt.entanglementlib.security.crypto.Mode;

import java.util.Arrays;

/// ARIA 블록 암호 알고리즘 전략 클래스입니다.
///
/// ARIA는 대한민국 국가 표준 암호 알고리즘으로, 128비트 블록 크기를 사용합니다.
/// BouncyCastle의 [ARIAEngine]을 사용하여 암호화/복호화를 수행합니다.
/// ARIA-128, ARIA-192, ARIA-256 키 길이를 지원하며, 다양한 운영 모드와
/// 패딩 방식을 설정할 수 있습니다.
///
/// 키는 네이티브 메모리에서 관리되며, 사용 후 즉시 소거됩니다.
///
/// @author Q. T. Felix
/// @see AbstractBlockCipher
/// @see CipherType#ARIA_128
/// @see CipherType#ARIA_192
/// @see CipherType#ARIA_256
/// @since 1.1.0
@Slf4j
public final class ARIAStrategy extends AbstractBlockCipher {

    /**
     * ARIAStrategy 생성자입니다.
     *
     * @param base ARIA 암호화 타입 ({@link CipherType#ARIA_128}, {@link CipherType#ARIA_192}, {@link CipherType#ARIA_256})
     */
    ARIAStrategy(@NotNull CipherType base) {
        super(base, new ARIAEngine());
    }

    /**
     * ARIAStrategy 인스턴스를 생성하는 팩토리 메소드입니다.
     *
     * @param base ARIA 암호화 타입 ({@link CipherType#ARIA_128}, {@link CipherType#ARIA_192}, {@link CipherType#ARIA_256})
     * @return 새 {@link ARIAStrategy} 인스턴스
     */
    public static ARIAStrategy create(@NotNull CipherType base) {
        return new ARIAStrategy(base);
    }

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
        ;

        // 사용 후 힙에 복사된 키 바이트 즉시 소거
        KeyDestroyHelper.zeroing(keyBytes);

        // iv 호출
        iv.exportData();
        byte[] ivH = iv.getSegmentData();
        if (ivH == null)
            throw new EntLibSecureIllegalStateException("IV를 생성해야 합니다!");

        if (mode != Mode.ECB) {
            if (isAead) {
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
            return new SensitiveDataContainer(result, true);
        } else {
            return new SensitiveDataContainer(output, true);
        }
    }

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
     * @return 알고리즘 이름 "ARIA"
     */
    @Override
    public String getAlgorithmName() {
        return "ARIA";
    }
}
