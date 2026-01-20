/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.key.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.util.Arrays;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;
import space.qu4nt.entanglementlib.experimental.crypto.key.strategy.EntLibAsymmetricKeyStrategy;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.detail.MLDSAStrategy;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * ML-DSA(Module-Lattice Digital Signature Algorithm) 알고리즘을 위한 비대칭 키 쌍 생성 전략 클래스입니다.
 * <p>
 * ML-DSA는 NIST에서 표준화한 PQC(Post-Quantum Cryptography) 전자 서명 알고리즘으로,
 * ML-DSA-44, ML-DSA-65, ML-DSA-87 파라미터 세트를 지원합니다.
 * {@link MLDSAStrategy}와 함께 사용됩니다.
 * </p>
 *
 * @author Q. T. Felix
 * @see EntLibAsymmetricKeyStrategy
 * @see MLDSAStrategy
 * @since 1.1.0
 */
@Slf4j
public final class MLDSAKeyStrategy implements EntLibAsymmetricKeyStrategy {

    /**
     * ML-DSA 알고리즘 파라미터입니다.
     */
    private final MLDSAParameters mldsaParameters;

    /**
     * {@link MLDSAStrategy}로부터 파라미터를 추출하여 인스턴스를 생성하는 생성자입니다.
     *
     * @param mldsaStrategy ML-DSA 서명 전략
     */
    private MLDSAKeyStrategy(MLDSAStrategy mldsaStrategy) {
        this.mldsaParameters = mldsaStrategy.findInternalParameters();
    }

    /**
     * {@link MLDSAKeyStrategy} 인스턴스를 생성하는 팩토리 메소드입니다.
     *
     * @param mldsaStrategy ML-DSA 서명 전략
     * @return 새 {@link MLDSAKeyStrategy} 인스턴스
     */
    public static MLDSAKeyStrategy create(@NotNull MLDSAStrategy mldsaStrategy) {
        return new MLDSAKeyStrategy(mldsaStrategy);
    }

    /**
     * ML-DSA 공개 키와 개인 키 쌍을 생성하여 반환하는 메소드입니다.
     * <p>
     * 반환되는 {@link Pair}의 첫 번째 요소는 공개 키, 두 번째 요소는 개인 키입니다.
     * </p>
     *
     * @return 공개 키와 개인 키의 쌍
     */
    @Override
    public Pair<EntLibCryptoKey, EntLibCryptoKey> generateKeyPair() {
        try {
            final Internal in = new Internal(mldsaParameters);
            return new Pair<>(in.pk(), in.sk());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * ML-DSA 키 생성을 위한 내부 헬퍼 클래스입니다.
     */
    private static class Internal {
        MLDSAParameters baseParam;
        private final byte[][] p;

        Internal(MLDSAParameters baseParam) throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException {
            this.baseParam = baseParam;
            this.p = calc();
        }

        EntLibCryptoKey pk() {
            return new EntLibCryptoKey(Arrays.concatenate(p[0], p[6]));
        }

        EntLibCryptoKey sk() {
            return new EntLibCryptoKey(Arrays.concatenate(new byte[][]{p[0], p[1], p[2], p[3], p[4], p[5]}));
        }

        private byte[][] calc() throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException {
            final Object engine = castEngine();
            Method generateKeyPairMethod = engine.getClass().getDeclaredMethod("generateKeyPair");
            generateKeyPairMethod.setAccessible(true);
            return (byte[][]) generateKeyPairMethod.invoke(engine);
        }

        Object castEngine() throws NoSuchMethodException, ClassNotFoundException, InvocationTargetException, InstantiationException, IllegalAccessException {
            Method engineMethod = Objects.requireNonNull(baseParam).getClass().getDeclaredMethod("getEngine", SecureRandom.class);
            engineMethod.setAccessible(true);
            Class<?> engineClass = Class.forName("org.bouncycastle.pqc.crypto.mldsa.MLDSAEngine");
            Constructor<?> engineConst = engineClass.getDeclaredConstructor(int.class, SecureRandom.class);
            engineConst.setAccessible(true);

            int k = baseParam.equals(MLDSAParameters.ml_dsa_44) || baseParam.equals(MLDSAParameters.ml_dsa_44_with_sha512) ? 2 :
                    baseParam.equals(MLDSAParameters.ml_dsa_65) || baseParam.equals(MLDSAParameters.ml_dsa_65_with_sha512) ? 3 :
                            baseParam.equals(MLDSAParameters.ml_dsa_87) || baseParam.equals(MLDSAParameters.ml_dsa_87_with_sha512) ? 5 : 3;
            return engineConst.newInstance(k, InternalFactory.getSafeRandom());
        }
    }
}
