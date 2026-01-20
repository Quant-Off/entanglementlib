/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.experimental.crypto.CipherType;
import space.qu4nt.entanglementlib.experimental.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;
import space.qu4nt.entanglementlib.experimental.crypto.key.strategy.detail.AESSymmetricKeyStrategy;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.EntLibCryptoStrategy;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.security.algorithm.Mode;
import space.qu4nt.entanglementlib.security.algorithm.Padding;
import space.qu4nt.entanglementlib.util.wrapper.Hex;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AES(Advanced Encryption Standard) 블록 암호 알고리즘 전략 클래스입니다.
 * <p>
 * BouncyCastle의 {@link AESEngine}을 사용하여 AES 암호화/복호화를 수행합니다.
 * AES-128, AES-192, AES-256 키 길이를 지원하며, 다양한 운영 모드(CBC, GCM, CTR 등)와
 * 패딩 방식을 설정할 수 있습니다.
 * </p>
 * <p>
 * 키는 네이티브 메모리에서 관리되며, 사용 후 즉시 소거됩니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see AbstractBlockCipher
 * @see CipherType#AES_128
 * @see CipherType#AES_192
 * @see CipherType#AES_256
 */
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
    public static AESStrategy create(@NotNull CipherType base) {
        return new AESStrategy(base);
    }

    /**
     * 평문을 AES 알고리즘으로 암호화하는 메소드입니다.
     * <p>
     * ECB 모드를 제외한 모든 모드에서 IV(초기화 벡터)가 자동으로 생성되며,
     * 결과는 {@code IV + CipherText} 형식으로 반환됩니다.
     * AEAD 모드(GCM, CCM)에서는 12바이트 IV를, 그 외 모드에서는 16바이트 IV를 사용합니다.
     * </p>
     *
     * @param key        암호화에 사용할 키
     * @param plainBytes 암호화할 평문 바이트 배열
     * @return 암호화된 바이트 배열 (IV + CipherText)
     * @throws IllegalStateException 암호화 실패 시
     */
    @Override
    public byte @NotNull [] encrypt(@NotNull EntLibCryptoKey key, final byte[] plainBytes) {
        try {
            boolean isAead = mode.isAead();
            byte[] iv;
            CipherParameters params;

            // 네이티브 메모리에서 키 바이트 배열 추출
            byte[] keyBytes = key.toByteArray();
            if (keyBytes == null)
                throw new RuntimeException("key null");
            KeyParameter keyParam = new KeyParameter(keyBytes);

            // 사용 후 힙에 복사된 키 바이트 즉시 소거
            KeyDestroyHelper.zeroing(keyBytes);

            // IV 생성 (ECB 제외)
            if (mode != Mode.ECB) {
                int ivLength = isAead ? 12 : 16; // GCM/CCM: 12 bytes, Others: 16 bytes (AES block size)
                iv = new byte[ivLength];
                InternalFactory.getSafeRandom().nextBytes(iv);

                if (isAead) {
                    // AEAD 모드는 AEADParameters 사용 (macSize = 128 bits)
                    params = new AEADParameters(keyParam, 128, iv);
                } else {
                    params = new ParametersWithIV(keyParam, iv);
                }
            } else {
                iv = new byte[0];
                params = keyParam;
            }

            byte[] output = processCipher(true, params, plainBytes);

            // 결과 반환: IV + CipherText (ECB 제외)
            if (mode != Mode.ECB) {
                byte[] result = new byte[iv.length + output.length];
                System.arraycopy(iv, 0, result, 0, iv.length);
                System.arraycopy(output, 0, result, iv.length, output.length);
                KeyDestroyHelper.zeroing(output);
                return result;
            } else {
                return output;
            }

        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * 암호문을 AES 알고리즘으로 복호화하는 메소드입니다.
     * <p>
     * 입력된 암호문에서 IV를 추출하여 복호화를 수행합니다.
     * AEAD 모드에서는 12바이트, 그 외 모드에서는 16바이트의 IV를 추출합니다.
     * </p>
     *
     * @param key        복호화에 사용할 키
     * @param ciphertext 복호화할 암호문 바이트 배열 (IV + CipherText)
     * @return 복호화된 평문 바이트 배열
     * @throws IllegalStateException    복호화 실패 시
     * @throws IllegalArgumentException 암호문이 IV보다 짧은 경우
     */
    @Override
    public byte @NotNull [] decrypt(@NotNull EntLibCryptoKey key, final byte[] ciphertext) {
        try {
            boolean isAead = mode.isAead();
            byte[] actualCiphertext;
            CipherParameters params;

            // 네이티브 메모리에서 키 바이트 배열 추출
            byte[] keyBytes = key.toByteArray();
            if (keyBytes == null)
                throw new RuntimeException("key null");
            KeyParameter keyParam = new KeyParameter(keyBytes);

            // 사용 후 힙에 복사된 키 바이트 즉시 소거
            KeyDestroyHelper.zeroing(keyBytes);

            if (mode != Mode.ECB) {
                int ivLength = isAead ? 12 : 16;
                if (ciphertext.length < ivLength) {
                    throw new IllegalArgumentException("Ciphertext too short to contain IV");
                }

                byte[] iv = Arrays.copyOfRange(ciphertext, 0, ivLength);
                actualCiphertext = Arrays.copyOfRange(ciphertext, ivLength, ciphertext.length);

                if (isAead) {
                    params = new AEADParameters(keyParam, 128, iv);
                } else {
                    params = new ParametersWithIV(keyParam, iv);
                }
            } else {
                actualCiphertext = ciphertext;
                params = keyParam;
            }

            return processCipher(false, params, actualCiphertext);

        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("Decryption failed: " + e.getMessage(), e);
        }
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

    /**
     * AES 전략들을 레지스트리에 등록하는 메소드입니다.
     *
     * @return AES 전략 맵
     * @deprecated {@link space.qu4nt.entanglementlib.experimental.crypto.bundle.AESStrategyBundle} 사용을 권장합니다.
     */
    @Deprecated(since = "1.1.0", forRemoval = true)
    public static Map<EntLibAlgorithmType, EntLibCryptoStrategy> registry() {
        return new ConcurrentHashMap<>(Map.of(
                CipherType.AES_128, new AESStrategy(CipherType.AES_128),
                CipherType.AES_192, new AESStrategy(CipherType.AES_192),
                CipherType.AES_256, new AESStrategy(CipherType.AES_256)
        ));
    }

    // 테스트용 psvm
    public static void main(String[] args) {
        byte[] plain = "Hello, AES Secure World!".getBytes(StandardCharsets.UTF_8);

        // 전략 패턴을 사용한 키 생성
        AESStrategy aesStrategy = new AESStrategy(CipherType.AES_256);
        aesStrategy.setMode(Mode.CFB).setPadding(Padding.NO);

        // AESKeyStrategy를 통해 키 생성
        AESSymmetricKeyStrategy keyStrategy = AESSymmetricKeyStrategy.create(aesStrategy);

        // try-with-resources로 키 자동 소거 보장
        try (EntLibCryptoKey key = keyStrategy.generateKey()) {
            // 키 확인 (테스트용 - 실제 운영 환경에서는 키를 로그에 찍으면 안 됨)
            MemorySegment keySegment = key.getKeySegment();
            byte[] keyBytes = keySegment.toArray(ValueLayout.JAVA_BYTE);
            log.info("Key (Hex): {}", Hex.toHexString(keyBytes));
            KeyDestroyHelper.zeroing(keyBytes); // 확인 후 즉시 소거

            // 암호화
            byte[] encrypted = aesStrategy.encrypt(key, plain);
            log.info("Encrypted: {}", Hex.toHexString(encrypted));

            // 복호화
            byte[] decrypted = aesStrategy.decrypt(key, encrypted);
            log.info("Decrypted: {}", Hex.toHexString(decrypted));
            log.info("Decrypted Plain: {}", new String(decrypted, StandardCharsets.UTF_8));
        } // 여기서 key.close()가 호출되어 네이티브 메모리 소거 및 해제됨
    }
}
