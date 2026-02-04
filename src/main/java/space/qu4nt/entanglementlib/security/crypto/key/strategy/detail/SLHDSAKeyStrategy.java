/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.key.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.util.Arrays;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.Unsafe;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.EntLibAsymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.SLHDSAStrategy;
import space.qu4nt.entanglementlib.util.wrapper.Pair;
import space.qu4nt.entanglementlib.util.wrapper.Tuple;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/// SLH-DSA(Stateless Hash-based Digital Signature Algorithm) 알고리즘을 위한 비대칭 키 쌍 생성 전략 클래스입니다.
///
/// SLH-DSA는 NIST에서 표준화한 PQC 전자 서명 알고리즘으로, 많은 파라미터 세트를 지원합니다.
/// [SLHDSAStrategy]와 함께 사용됩니다.
///
/// # Safety
///
/// 이 알고리즘에 대해, 모든 로직이 네이티브에서 아직 안정화되지 않았습니다.
///
/// @author Q. T. Felix
/// @see EntLibAsymmetricKeyStrategy
/// @see SLHDSAStrategy
/// @since 1.1.0
@Unsafe
@Slf4j
@ApiStatus.Obsolete
public final class SLHDSAKeyStrategy implements EntLibAsymmetricKeyStrategy {

    /**
     * SLH-DSA 알고리즘 파라미터입니다.
     */
    private final SLHDSAParameters slhdsaParameters;

    /**
     * {@link SLHDSAStrategy}로부터 파라미터를 추출하여 인스턴스를 생성하는 생성자입니다.
     *
     * @param slhdsaParameters SLH-DSA 서명 BC 파라미터
     */
    private SLHDSAKeyStrategy(SLHDSAParameters slhdsaParameters) {
        this.slhdsaParameters = slhdsaParameters;
    }

    /**
     * {@link SLHDSAKeyStrategy} 인스턴스를 생성하는 팩토리 메소드입니다.
     *
     * @param slhdsaParameters SLH-DSA 서명 BC 파라미터
     * @return 새 {@link SLHDSAKeyStrategy} 인스턴스
     */
    @ApiStatus.Internal
    public static SLHDSAKeyStrategy create(@NotNull SLHDSAParameters slhdsaParameters) {
        return new SLHDSAKeyStrategy(slhdsaParameters);
    }

    /**
     * SLH-DSA 공개 키와 개인 키 쌍을 생성하여 반환하는 메소드입니다.
     * <p>
     * 반환되는 {@link Pair}의 첫 번째 요소는 공개 키, 두 번째 요소는 개인 키입니다.
     *
     * @return 공개 키와 개인 키의 쌍
     */
    @Override
    public Pair<SensitiveDataContainer, SensitiveDataContainer> generateKeyPair() {
        try {
            final Internal in = new Internal(slhdsaParameters);
            return in.gen();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /// SLH-DSA 키 생성을 위한 내부 헬퍼 클래스입니다.
    ///
    /// BouncyCastle 라이브러리에서 SLH-DSA는 sha2 엔진과 shake 엔진이 나누어져 있습니다.
    /// [SLHDSAParameters] 클래스 내에 package-private 처리된 엔진 호출 메소드를
    /// 사용하면 개별 엔진 클래스를 따로 호출할 필요 없이 사용 가능하지만, 리플렉션을 사용하여
    /// 접근하기 때문에 별도의 엔진 메소드를 차별화했습니다.
    ///
    /// # Safety
    ///
    /// 이 기능은 `BouncyCastle`의 `SLH-DSA` 엔진을 리플렉션으로 호출하여 키 생성을
    /// 수행하도록 하는 내부 클래스입니다. 이 기능은 `BC`의존성이 제거됨과 동시에
    /// 제거됩니다.
    ///
    /// @author Q. T. Felix
    /// @since 1.1.0
    @Unsafe
    @ApiStatus.Obsolete(since = "1.1.0")
    @ApiStatus.Internal
    private static class Internal {
        SLHDSAParameters baseParam;
        Object engine;

        private final Tuple<byte[], byte[], byte[]> tuple;

        Internal(SLHDSAParameters baseParam) throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException, NoSuchFieldException {
            this.baseParam = baseParam;
            this.tuple = calc(baseParam.getName().contains("with") || (baseParam.getName().startsWith("sha2-")));
        }

        // pk, sk
        Pair<SensitiveDataContainer, SensitiveDataContainer> gen() throws NoSuchFieldException, ClassNotFoundException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException {
            byte[] pkRoot = pkC(); // htpubkey(pkroot)
            byte[] sk = skC(pkRoot);
            final byte[] safeMixPK = Arrays.concatenate(tuple.getThird(), pkRoot);
            return new Pair<>(
                    new SensitiveDataContainer(safeMixPK, true),
                    new SensitiveDataContainer(sk, true)
            );
        }

        private byte[] pkC() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException, NoSuchFieldException {
            Method init = engine.getClass().getDeclaredMethod("init", byte[].class);
            init.setAccessible(true);
            //noinspection PrimitiveArrayArgumentToVarargsMethod
            init.invoke(engine, tuple.getThird());

            Class<?> engineParent = Class.forName("org.bouncycastle.pqc.crypto.slhdsa.SLHDSAEngine");
            Class<?> ht = Class.forName("org.bouncycastle.pqc.crypto.slhdsa.HT");
            Constructor<?> htConst = ht.getDeclaredConstructor(engineParent, byte[].class, byte[].class);
            htConst.setAccessible(true);
            @SuppressWarnings("JavaReflectionInvocation") Object htObj = htConst.newInstance(engine, tuple.getFirst(), tuple.getThird());
            Field htPubKeyField = htObj.getClass().getDeclaredField("htPubKey");
            htPubKeyField.setAccessible(true);
            return (byte[]) htPubKeyField.get(htObj);
        }

        private byte[] skC(final byte[] pkroot) {
            return Arrays.concatenate(new byte[][]{tuple.getFirst(), tuple.getSecond(), tuple.getThird(), pkroot});
        }

        // skSeed, skPrf, pkSeed
        private Tuple<byte[], byte[], byte[]> calc(boolean sha2) throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException, NoSuchFieldException {
            this.engine = sha2 ? castSha2Engine() : castShakeEngine();
            Field nField = engine.getClass().getSuperclass().getDeclaredField("N");
            nField.setAccessible(true);
            int n = (int) nField.get(engine);
            byte[] skSeed = SensitiveDataContainer.generateSafeRandomBytes(n);
            byte[] skPrf = SensitiveDataContainer.generateSafeRandomBytes(n);
            byte[] pkSeed = SensitiveDataContainer.generateSafeRandomBytes(n);
            return new Tuple<>(skSeed, skPrf, pkSeed);
        }

        Object castSha2Engine() throws NoSuchMethodException, ClassNotFoundException, InvocationTargetException, InstantiationException, IllegalAccessException {
            Class<?> sha2EngineProviderClass = Class.forName("org.bouncycastle.pqc.crypto.slhdsa.SLHDSAEngine$Sha2Engine");
            final int n = baseParam.getN(); // 키 사이즈 바이트
            Constructor<?> engineConst = sha2EngineProviderClass.getDeclaredConstructor(int.class, int.class, int.class, int.class, int.class, int.class);
            engineConst.setAccessible(true);

            int[] constParamVals;
            if (baseParam.equals(SLHDSAParameters.sha2_128f)) {
                constParamVals = new int[]{22, 6, 33, 66};
            } else if (baseParam.equals(SLHDSAParameters.sha2_128s)) {
                constParamVals = new int[]{7, 12, 14, 63};
            } else if (baseParam.equals(SLHDSAParameters.sha2_192f)) {
                constParamVals = new int[]{22, 8, 33, 66};
            } else if (baseParam.equals(SLHDSAParameters.sha2_192s)) {
                constParamVals = new int[]{7, 14, 17, 63};
            } else if (baseParam.equals(SLHDSAParameters.sha2_256f)) {
                constParamVals = new int[]{17, 9, 35, 68};
            } else if (baseParam.equals(SLHDSAParameters.sha2_256s)) {
                constParamVals = new int[]{8, 14, 22, 64};
            } else {
                constParamVals = new int[]{8, 14, 22, 64};
            }

            return engineConst.newInstance(n, 16, constParamVals[0], constParamVals[1], constParamVals[2], constParamVals[3]);
        }

        Object castShakeEngine() throws NoSuchMethodException, ClassNotFoundException, InvocationTargetException, InstantiationException, IllegalAccessException {
            Class<?> shakeEngineProviderClass = Class.forName("org.bouncycastle.pqc.crypto.slhdsa.SLHDSAEngine$Shake256Engine");
            final int n = baseParam.getN(); // 키 사이즈 바이트
            Constructor<?> engineConst = shakeEngineProviderClass.getDeclaredConstructor(int.class, int.class, int.class, int.class, int.class, int.class);
            engineConst.setAccessible(true);

            int[] constParamVals;
            if (baseParam.equals(SLHDSAParameters.shake_128f)) {
                constParamVals = new int[]{22, 6, 33, 66};
            } else if (baseParam.equals(SLHDSAParameters.shake_128s)) {
                constParamVals = new int[]{7, 12, 14, 63};
            } else if (baseParam.equals(SLHDSAParameters.shake_192f)) {
                constParamVals = new int[]{22, 8, 33, 66};
            } else if (baseParam.equals(SLHDSAParameters.shake_192s)) {
                constParamVals = new int[]{7, 14, 17, 63};
            } else if (baseParam.equals(SLHDSAParameters.shake_256f)) {
                constParamVals = new int[]{17, 9, 35, 68};
            } else if (baseParam.equals(SLHDSAParameters.shake_256s)) {
                constParamVals = new int[]{8, 14, 22, 64};
            } else {
                constParamVals = new int[]{8, 14, 22, 64};
            }

            return engineConst.newInstance(n, 16, constParamVals[0], constParamVals[1], constParamVals[2], constParamVals[3]);
        }
    }
}
