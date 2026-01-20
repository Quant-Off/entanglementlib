/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package space.qu4nt.entanglementlib.experimental.crypto.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.experimental.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.experimental.crypto.SignatureType;
import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;
import space.qu4nt.entanglementlib.experimental.crypto.key.strategy.detail.MLDSAKeyStrategy;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.SignatureStrategy;
import space.qu4nt.entanglementlib.util.wrapper.Hex;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import java.nio.charset.StandardCharsets;

/**
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Slf4j
public final class MLDSAStrategy implements SignatureStrategy {

    private final SignatureType type;

    MLDSAStrategy(@NotNull SignatureType type) {
        this.type = type;
    }

    /**
     * MLDSAStrategy 인스턴스를 생성합니다.
     *
     * @param type SignatureType (ML_DSA_44, ML_DSA_65, ML_DSA_87)
     * @return 새 MLDSAStrategy 인스턴스
     */
    public static MLDSAStrategy create(@NotNull SignatureType type) {
        return new MLDSAStrategy(type);
    }

    @Override
    public byte @NotNull [] sign(@NotNull EntLibCryptoKey keyPrivate, byte[] plainBytes) {
        if (plainBytes == null) {
            throw new RuntimeException("plain null");
        }
        // 서명 low-level api 호출
        MLDSASigner signer = new MLDSASigner();

        // 네이티브 메모리에서 키 바이트 배열 추출
        byte @Nullable [] keyBytes = keyPrivate.toByteArray();
        if (keyBytes == null)
            throw new RuntimeException("key null");
        MLDSAPrivateKeyParameters skParams = new MLDSAPrivateKeyParameters(findInternalParameters(), keyBytes);

        // 서명기 초기화
        signer.init(true, skParams);

        if (skParams == null && !skParams.isPrivate())
            throw new RuntimeException("key is not private");

        signer.update(plainBytes, 0, plainBytes.length);
        try {
            return signer.generateSignature();
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(@NotNull EntLibCryptoKey keyPublic, byte[] plainBytes, byte[] signature) {
        if (plainBytes == null || signature == null) {
            throw new RuntimeException("plain or sig null");
        }
        // 서명 low-level api 호출
        MLDSASigner signer = new MLDSASigner();

        // 네이티브 메모리에서 키 바이트 배열 추출
        byte @Nullable [] keyBytes = keyPublic.toByteArray();
        if (keyBytes == null)
            throw new RuntimeException("key null");
        MLDSAPublicKeyParameters pkParams = new MLDSAPublicKeyParameters(findInternalParameters(), keyBytes);

        // 검증기 초기화
        signer.init(false, pkParams);

        if (pkParams == null && pkParams.isPrivate())
            throw new RuntimeException("key is not public");

        signer.update(plainBytes, 0, plainBytes.length);
        return signer.verifySignature(signature);
    }

    @Override
    public String getAlgorithmName() {
        return "ML-DSA";
    }

    @Override
    public EntLibAlgorithmType getAlgorithmType() {
        return type;
    }

    public MLDSAParameters findInternalParameters() {
        return type.equals(SignatureType.ML_DSA_44) ? MLDSAParameters.ml_dsa_44 :
                type.equals(SignatureType.ML_DSA_65) ? MLDSAParameters.ml_dsa_65 :
                        type.equals(SignatureType.ML_DSA_87) ? MLDSAParameters.ml_dsa_87 : MLDSAParameters.ml_dsa_65;
    }

    public static void main(String[] args) {
        byte[] plains = "Hello, ML-DSA Secure Signature World!".getBytes(StandardCharsets.UTF_8);
        MLDSAStrategy mldsaStrategy = new MLDSAStrategy(SignatureType.ML_DSA_65);

        MLDSAKeyStrategy key = MLDSAKeyStrategy.create(mldsaStrategy);
        Pair<EntLibCryptoKey, EntLibCryptoKey> keyPair = key.generateKeyPair();

        // sign
        byte[] sig = mldsaStrategy.sign(keyPair.getSecond(), plains);
        log.info("Signature: {}", Hex.toHexString(sig));

//        Thread vT = new Thread(() -> {
        MLDSAStrategy mldsaStrategyVerifier = new MLDSAStrategy(SignatureType.ML_DSA_65);
        log.info("Verify: {}", mldsaStrategyVerifier.verify(keyPair.getFirst(), plains, sig));
//        });

//        vT.start();
    }
}
