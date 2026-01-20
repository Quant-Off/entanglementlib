/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.strategy.detail;

import lombok.Getter;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.paddings.*;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.experimental.crypto.CipherType;
import space.qu4nt.entanglementlib.experimental.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.AEADCipherStrategy;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.BlockCipherStrategy;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.security.algorithm.Digest;
import space.qu4nt.entanglementlib.security.algorithm.Mode;
import space.qu4nt.entanglementlib.security.algorithm.Padding;

import java.util.Arrays;

/**
 * 블록 암호 알고리즘의 공통 기능을 제공하는 추상 클래스입니다.
 * <p>
 * AES, ARIA 등의 블록 암호 구현체가 이 클래스를 상속합니다.
 * 다양한 운영 모드(CBC, GCM, CTR 등)와 패딩 방식을 지원합니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see BlockCipherStrategy
 * @see AEADCipherStrategy
 */
public abstract class AbstractBlockCipher implements BlockCipherStrategy, AEADCipherStrategy {

    /**
     * 암호화 알고리즘 타입입니다.
     */
    private final @NotNull CipherType base;

    /**
     * BouncyCastle 블록 암호 엔진입니다.
     */
    private final @NotNull BlockCipher blockCipherEngine;

    /**
     * 현재 설정된 운영 모드입니다.
     */
    @Getter
    Mode mode;

    /**
     * 현재 설정된 패딩 방식입니다.
     */
    @Getter
    Padding padding;

    /**
     * 현재 설정된 다이제스트입니다.
     */
    @Getter
    @Nullable Digest digest;

    /**
     * AAD(Additional Authenticated Data) 데이터입니다.
     */
    private byte[] aad;

    /**
     * 블록 암호 추상 클래스의 생성자입니다.
     *
     * @param base              암호화 알고리즘 타입
     * @param blockCipherEngine BouncyCastle 블록 암호 엔진
     */
    protected AbstractBlockCipher(final @NotNull CipherType base, @NotNull BlockCipher blockCipherEngine) {
        this.base = base;
        this.blockCipherEngine = blockCipherEngine;
        this.mode = Mode.CBC;
        this.padding = Padding.PKCS7;
        this.digest = null;
        this.aad = null;
    }

    @Override
    public AbstractBlockCipher setMode(@NotNull Mode mode) {
        this.mode = mode;
        return this;
    }

    @Override
    public AbstractBlockCipher setPadding(@NotNull Padding padding) {
        this.padding = padding;
        return this;
    }

    @Override
    public AbstractBlockCipher setDigest(@NotNull Digest digest) {
        this.digest = digest;
        return this;
    }

    @Override
    public AbstractBlockCipher updateAAD(byte[] aad) {
        if (aad != null) {
            this.aad = Arrays.copyOf(aad, aad.length);
        } else {
            this.aad = null;
        }
        return this;
    }

    @Override
    public EntLibAlgorithmType getAlgorithmType() {
        return base;
    }

    protected byte[] processCipher(boolean encrypt, CipherParameters params, byte[] input) throws InvalidCipherTextException {
        boolean isAead = mode.isAead();
        byte[] output;
        int len;

        if (isAead) {
            AEADBlockCipher cipher = createAeadCipher();
            cipher.init(encrypt, params);
            
            // AAD 설정
            if (aad != null) {
                cipher.processAADBytes(aad, 0, aad.length);
            }

            output = new byte[cipher.getOutputSize(input.length)];
            len = cipher.processBytes(input, 0, input.length, output, 0);
            len += cipher.doFinal(output, len);
        } else {
            BufferedBlockCipher cipher = createBufferedCipher();
            cipher.init(encrypt, params);
            output = new byte[cipher.getOutputSize(input.length)];
            len = cipher.processBytes(input, 0, input.length, output, 0);
            len += cipher.doFinal(output, len);
        }

        KeyDestroyHelper.destroy(params);

        if (len < output.length) {
            return Arrays.copyOf(output, len);
        }
        return output;
    }

    BufferedBlockCipher createBufferedCipher() {
        BlockCipher modeCipher = switch (mode) {
            case ECB -> blockCipherEngine;
            case CBC -> CBCBlockCipher.newInstance(blockCipherEngine);
            case CFB -> CFBBlockCipher.newInstance(blockCipherEngine, 128);
            case OFB -> new OFBBlockCipher(blockCipherEngine, 128);
            case CTR -> SICBlockCipher.newInstance(blockCipherEngine);
            default -> throw new UnsupportedOperationException("Unsupported mode: " + mode);
        };

        BlockCipherPadding paddingImpl = getPaddingImpl();
        if (paddingImpl != null) {
            return new PaddedBufferedBlockCipher(modeCipher, paddingImpl);
        }
        return new DefaultBufferedBlockCipher(modeCipher);
    }

    AEADBlockCipher createAeadCipher() {
        return switch (mode) {
            case AEAD_GCM -> GCMBlockCipher.newInstance(blockCipherEngine);
            case AEAD_CCM -> CCMBlockCipher.newInstance(blockCipherEngine);
            default -> throw new UnsupportedOperationException("Unsupported AEAD mode: " + mode);
        };
    }

    BlockCipherPadding getPaddingImpl() {
        return switch (padding) {
            case PKCS5, PKCS7 -> new PKCS7Padding();
            case ISO7816 -> new ISO7816d4Padding();
            case ISO10126 -> new ISO10126d2Padding();
            case ZERO_BYTE -> new ZeroBytePadding();
            case NO, PKCS1, OAEP_AND_MGF1 -> null;
        };
    }
}
