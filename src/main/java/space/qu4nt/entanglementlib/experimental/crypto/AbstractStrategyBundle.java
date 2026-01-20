/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.EntLibCryptoStrategy;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 암호화 스트레티지와 키 스트레티지를 함께 래핑하여 레지스트리에 등록하기 위한 추상 클래스입니다.
 * <p>
 * 이 클래스를 상속하는 번들은 생성 시 자동으로 전역 번들 목록에 등록되며,
 * {@link EntLibCryptoRegistry}에서 모든 번들의 스트레티지를 수집하여 사용합니다.
 * </p>
 *
 * <h2>사용법</h2>
 * <pre>{@code
 * public final class AESStrategyBundle extends AbstractStrategyBundle {
 *
 *     // 싱글톤 인스턴스 - static 블록에서 자동 등록
 *     private static final AESStrategyBundle INSTANCE = new AESStrategyBundle();
 *
 *     private AESStrategyBundle() {}
 *
 *     @Override
 *     protected void registerStrategies() {
 *         register(CipherType.AES_128, new AESStrategy(CipherType.AES_128));
 *         register(CipherType.AES_192, new AESStrategy(CipherType.AES_192));
 *         register(CipherType.AES_256, new AESStrategy(CipherType.AES_256));
 *     }
 * }
 * }</pre>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
public abstract class AbstractStrategyBundle implements RegistrableStrategy {

    /**
     * 등록된 모든 번들을 저장하는 전역 집합입니다.
     * <p>
     * Thread-safe한 {@link Set}을 사용합니다.
     * </p>
     */
    private static final Set<AbstractStrategyBundle> REGISTERED_BUNDLES = ConcurrentHashMap.newKeySet();

    /**
     * 이 번들이 관리하는 스트레티지 맵입니다.
     */
    private final Map<EntLibAlgorithmType, EntLibCryptoStrategy> strategies = new ConcurrentHashMap<>();

    /**
     * 스트레티지가 이미 등록되었는지 여부를 나타내는 플래그입니다.
     */
    private volatile boolean initialized = false;

    /**
     * 기본 생성자입니다.
     * <p>
     * 인스턴스 생성 시 자동으로 전역 번들 목록에 등록됩니다.
     * </p>
     */
    protected AbstractStrategyBundle() {
        REGISTERED_BUNDLES.add(this);
    }

    /**
     * 하위 클래스에서 구현하여 스트레티지들을 등록하는 메소드입니다.
     * <p>
     * {@link #register(EntLibAlgorithmType, EntLibCryptoStrategy)} 메소드를 사용하여 등록합니다.
     * </p>
     */
    protected abstract void registerStrategies();

    /**
     * 스트레티지를 내부 맵에 등록하는 메소드입니다.
     *
     * @param type     알고리즘 타입
     * @param strategy 등록할 스트레티지
     */
    protected final void register(@NotNull EntLibAlgorithmType type, @NotNull EntLibCryptoStrategy strategy) {
        strategies.put(type, strategy);
    }

    /**
     * 이 번들의 모든 스트레티지를 반환하는 메소드입니다.
     * <p>
     * 처음 호출 시 {@link #registerStrategies()}가 실행됩니다.
     * </p>
     *
     * @return 등록된 스트레티지 맵 (읽기 전용)
     */
    @Override
    public final Map<EntLibAlgorithmType, EntLibCryptoStrategy> getStrategies() {
        if (!initialized) {
            synchronized (this) {
                if (!initialized) {
                    registerStrategies();
                    initialized = true;
                }
            }
        }
        return Collections.unmodifiableMap(strategies);
    }

    /**
     * 등록된 모든 번들에서 스트레티지를 수집하여 반환하는 메소드입니다.
     *
     * @return 모든 번들의 스트레티지를 합친 맵
     */
    public static Map<EntLibAlgorithmType, EntLibCryptoStrategy> collectAllStrategies() {
        Map<EntLibAlgorithmType, EntLibCryptoStrategy> result = new ConcurrentHashMap<>();
        for (AbstractStrategyBundle bundle : REGISTERED_BUNDLES) {
            result.putAll(bundle.getStrategies());
        }
        return result;
    }

    /**
     * 등록된 번들의 수를 반환하는 메소드입니다.
     * <p>
     * 테스트 및 디버깅 용도로 사용됩니다.
     * </p>
     *
     * @return 등록된 번들 수
     */
    public static int registeredBundleCount() {
        return REGISTERED_BUNDLES.size();
    }

}
