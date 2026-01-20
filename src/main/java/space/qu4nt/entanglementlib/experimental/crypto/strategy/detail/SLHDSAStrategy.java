/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.experimental.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.experimental.crypto.SignatureType;
import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;
import space.qu4nt.entanglementlib.experimental.crypto.key.strategy.detail.SLHDSAKeyStrategy;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.SignatureStrategy;
import space.qu4nt.entanglementlib.util.wrapper.Hex;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

/**
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Slf4j
public final class SLHDSAStrategy implements SignatureStrategy {

    private final SignatureType type;

    SLHDSAStrategy(@NotNull SignatureType type) {
        this.type = type;
    }

    /**
     * SLHDSAStrategy 인스턴스를 생성합니다.
     *
     * @param type SignatureType (SLH_DSA bundle)
     * @return 새 SLHDSAStrategy 인스턴스
     */
    public static SLHDSAStrategy create(@NotNull SignatureType type) {
        return new SLHDSAStrategy(type);
    }

    @Override
    public byte @NotNull [] sign(@NotNull EntLibCryptoKey keyPrivate, byte[] plainBytes) {
        if (plainBytes == null) {
            throw new RuntimeException("plain null");
        }
        // 서명 low-level api 호출
        SLHDSASigner signer = new SLHDSASigner();

        // 네이티브 메모리에서 키 바이트 배열 추출
        byte @Nullable [] keyBytes = keyPrivate.toByteArray();
        if (keyBytes == null)
            throw new RuntimeException("key null");
        SLHDSAPrivateKeyParameters skParams = new SLHDSAPrivateKeyParameters(findInternalParameters(), keyBytes);

        // 서명기 초기화
        signer.init(true, skParams);

        if (skParams == null && !skParams.isPrivate())
            throw new RuntimeException("key is not private");

        return signer.generateSignature(plainBytes);
    }

    @Override
    public boolean verify(@NotNull EntLibCryptoKey keyPublic, byte[] plainBytes, byte[] signature) {
        if (plainBytes == null || signature == null) {
            throw new RuntimeException("plain or sig null");
        }
        // 서명 low-level api 호출
        SLHDSASigner signer = new SLHDSASigner();

        // 네이티브 메모리에서 키 바이트 배열 추출
        byte @Nullable [] keyBytes = keyPublic.toByteArray();
        if (keyBytes == null)
            throw new RuntimeException("key null");
        SLHDSAPublicKeyParameters pkParams = new SLHDSAPublicKeyParameters(findInternalParameters(), keyBytes);

        // 검증기 초기화
        signer.init(false, pkParams);

        if (pkParams == null && pkParams.isPrivate())
            throw new RuntimeException("key is not public");

        return signer.verifySignature(plainBytes, signature);
    }

    @Override
    public String getAlgorithmName() {
        return "ML-DSA";
    }

    @Override
    public EntLibAlgorithmType getAlgorithmType() {
        return type;
    }

    public SLHDSAParameters findInternalParameters() {
        return switch (type) {
            case SLH_DSA_SHA2_128s -> SLHDSAParameters.sha2_128s;
            case SLH_DSA_SHA2_128f -> SLHDSAParameters.sha2_128f;
            case SLH_DSA_SHA2_192s -> SLHDSAParameters.sha2_192s;
            case SLH_DSA_SHA2_192f -> SLHDSAParameters.sha2_192f;
            case SLH_DSA_SHA2_256s -> SLHDSAParameters.sha2_256s;
            case SLH_DSA_SHA2_256f -> SLHDSAParameters.sha2_256f;
            case SLH_DSA_SHAKE_128s -> SLHDSAParameters.shake_128s;
            case SLH_DSA_SHAKE_128f -> SLHDSAParameters.shake_128f;
            case SLH_DSA_SHAKE_192s -> SLHDSAParameters.shake_192s;
            case SLH_DSA_SHAKE_192f -> SLHDSAParameters.shake_192f;
            case SLH_DSA_SHAKE_256s -> SLHDSAParameters.shake_256s;
            case SLH_DSA_SHAKE_256f -> SLHDSAParameters.shake_256f;
            default -> SLHDSAParameters.sha2_256s;
        };
    }

    public static void main(String[] args) {
        byte[] plains = "Hello, SLH-DSA Secure Signature World!".getBytes(StandardCharsets.UTF_8);
        SLHDSAStrategy slhdsaStrategy = new SLHDSAStrategy(SignatureType.SLH_DSA_SHA2_128s);

        SLHDSAKeyStrategy key = SLHDSAKeyStrategy.create(slhdsaStrategy);
        Pair<EntLibCryptoKey, EntLibCryptoKey> keyPair = key.generateKeyPair();
        // key
        log.info("\nPK: {}\nSK: {}", Hex.toHexString(keyPair.getFirst().getKeySegment().toArray(ValueLayout.JAVA_BYTE)), Hex.toHexString(keyPair.getSecond().getKeySegment().toArray(ValueLayout.JAVA_BYTE)));

        // sign
        byte[] sig = slhdsaStrategy.sign(keyPair.getSecond(), plains);
        log.info("Signature: {}", Hex.toHexString(sig));

//        Thread vT = new Thread(() -> {
            SLHDSAStrategy slhdsaStrategyVerifier = new SLHDSAStrategy(SignatureType.SLH_DSA_SHA2_128s);
            log.info("Verify: {}", slhdsaStrategyVerifier.verify(keyPair.getFirst(), plains, sig));
//        });

//        vT.start();
    }
}
