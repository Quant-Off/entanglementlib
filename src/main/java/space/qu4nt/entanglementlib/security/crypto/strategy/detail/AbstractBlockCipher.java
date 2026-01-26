/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy.detail;

import lombok.Getter;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.paddings.*;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalArgumentException;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoCipherProcessException;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.security.crypto.*;
import space.qu4nt.entanglementlib.security.crypto.Digest;
import space.qu4nt.entanglementlib.security.crypto.strategy.AEADCipherStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.BlockCipherStrategy;

import java.nio.ByteBuffer;
import java.util.Arrays;

/// 블록 암호 알고리즘의 공통 기능을 제공하는 추상 클래스입니다.
///
/// AES, ARIA 등의 블록 암호 구현체가 이 클래스를 상속합니다.
/// 다양한 운영 모드(CBC, GCM, CTR 등)와 패딩 방식을 지원합니다.
///
/// @author Q. T. Felix
/// @see BlockCipherStrategy
/// @see AEADCipherStrategy
/// @since 1.1.0
public abstract class AbstractBlockCipher implements BlockCipherStrategy, AEADCipherStrategy {

    /**
     * 암호화 알고리즘 타입입니다.
     */
    private final @NotNull CipherType base;

    /**
     * BouncyCastle 블록 암호 엔진입니다.
     */
    private final @NotNull BlockCipher blockCipherEngine;

    protected SensitiveDataContainer iv;

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
    private byte[] aad; // todo: sdc

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
    public void iv(Object raw) throws EntLibSecureIllegalArgumentException {
        boolean isAead = mode.isAead();
        switch (raw) {
            case byte[] b -> this.iv = new SensitiveDataContainer(b, true);
            case Integer i -> {
                if (isAead && i != 12)
                    throw new EntLibSecureIllegalArgumentException("AEAD 지원 모드의 경우 IV의 길이는 12이어야 합니다!");
                if (!isAead && i != 16)
                    throw new EntLibSecureIllegalArgumentException("일반 모드에서 IV의 길이는 16이어야 합니다!");
                this.iv = new SensitiveDataContainer(i);
            }
            case SensitiveDataContainer s -> this.iv = s;
            case null, default -> throw new EntLibSecureIllegalArgumentException("유효한 IV 할당 타입이 아닙니다!");
        }
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

    protected byte[] processCipher(boolean encrypt, CipherParameters params, Object input) throws EntLibCryptoCipherProcessException, EntLibSecureIllegalStateException {
        boolean isAead = mode.isAead();
        byte[] output;
        int len;

        if (input instanceof byte[] b) {
            input = b.clone();
            KeyDestroyHelper.zeroing(b);
        } else if (input instanceof SensitiveDataContainer s) {
            s.exportData();
            input = s.getSegmentData();
        } else if (input instanceof ByteBuffer bb) {
            final byte[] arr = new byte[bb.remaining()];
            input = bb.get(arr);
            KeyDestroyHelper.zeroing(arr);
        }

        try {
            byte[] inputWrap = (byte[]) input;
            if (inputWrap == null)
                throw new EntLibSecureIllegalStateException("""
                        입력값의 명시적 형 변환 결과(역참조)가 null을 가리킵니다! 입력값이 가진 타입 또는 그 자체에 문제가 있을 수 있습니다.
                        \t\t1. 입력값의 타입은 '바이트 배열', 'SensitiveDataContainer', 'ByteBuffer' 중 하나여야 합니다.
                        \t\t2. 타입 할당에 문제가 없는데 이 예외가 발생했다면, 입력값이 올바른 값을 가리키지 않고 있거나, 배열 사이즈가 잘못 할당되었을 수 있습니다.""");
            if (isAead) {
                AEADBlockCipher cipher = createAeadCipher();
                cipher.init(encrypt, params);

                // AAD 설정
                if (aad != null)
                    cipher.processAADBytes(aad, 0, aad.length);

                output = new byte[cipher.getOutputSize(inputWrap.length)];
                len = cipher.processBytes(inputWrap, 0, inputWrap.length, output, 0);
                len += cipher.doFinal(output, len);
            } else {
                BufferedBlockCipher cipher = createBufferedCipher();
                cipher.init(encrypt, params);
                output = new byte[cipher.getOutputSize(inputWrap.length)];
                len = cipher.processBytes(inputWrap, 0, inputWrap.length, output, 0);
                len += cipher.doFinal(output, len);
            }
        } catch (Exception e) {
            throw new EntLibCryptoCipherProcessException("BlockCipher 암호화에 실패했습니다! 이 이유는 여러가지가 있지만, 대표적으로 다음과 같습니다.\n" +
                    "\t\t1. IV(초기화 벡터) 값이 외부에서 할당되었고, 암호문에 체이닝하지 않은 상태지만, 복호화 과정에서 IV를 추론하려고 하는 경우\n" +
                    "\t\t2. 암호문(ciphertext) 데이터 컨테이너의 내부 상태가 변질되었거나 소거된 경우\n" +
                    "\t\t3. 키 데이터 컨테이너의 내부 상태가 변질되었거나 소거된 경우", e);
        }

// todo:       KeyDestroyHelper.destroy(params);

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
