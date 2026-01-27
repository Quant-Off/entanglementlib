/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.security.crypto.bundle.BundleStaticCaller;
import space.qu4nt.entanglementlib.security.crypto.key.EntLibKey;
import space.qu4nt.entanglementlib.security.crypto.strategy.EntLibCryptoStrategy;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/// 암호화 스트레티지 레지스트리 클래스입니다.
///
/// 모든 암호화 스트레티지와 키 스트레티지는 [AbstractStrategyBundle]을 통해
/// 이 레지스트리에 자동으로 등록됩니다.
/// ## 새로운 알고리즘 추가 방법
///
/// 1. [AbstractStrategyBundle]을 상속하는 번들 클래스 생성
/// 2. 번들 클래스에서 `registerStrategies()` 메소드 구현
/// 3. 이 클래스의 static 블록에서 번들 인스턴스 참조 추가
///
/// @author Q. T. Felix
/// @see AbstractStrategyBundle
/// @see RegistrableStrategy
/// @since 1.1.0
public final class EntLibCryptoRegistry {

    /**
     * 알고리즘 타입과 스트레티지를 매핑하는 레지스트리 맵입니다.
     */
    static final Map<EntLibAlgorithmType, EntLibCryptoStrategy> ALG_REGISTRY = new ConcurrentHashMap<>();

    /**
     * 알고리즘 타입과 키 스트레티지를 매핑하는 레지스트리 맵입니다.
     */
    static final Map<EntLibAlgorithmType, EntLibKey> KEY_REGISTRY = new ConcurrentHashMap<>();

    static {
        // 각 번들의 싱글톤 인스턴스를 참조하여 자동 등록 트리거
        // AbstractStrategyBundle 생성자에서 전역 번들 목록에 자동 추가됨
        BundleStaticCaller.call();

        // 모든 등록된 번들에서 스트레티지 수집
        ALG_REGISTRY.putAll(AbstractStrategyBundle.collectAllAlgStrategies());
        KEY_REGISTRY.putAll(AbstractStrategyBundle.collectAllKeyStrategies());
    }

    /**
     * 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    private EntLibCryptoRegistry() {
    }

    /**
     * 지정된 알고리즘 타입에 해당하는 스트레티지를 반환하는 메소드입니다.
     *
     * @param type  알고리즘 타입
     * @param clazz 반환받을 스트레티지 클래스 타입
     * @param <T>   스트레티지 타입
     * @return 해당 타입의 스트레티지
     * @throws UnsupportedOperationException 지원하지 않는 타입인 경우
     */
    public static <T extends EntLibCryptoStrategy> T getAlgStrategy(@NotNull EntLibAlgorithmType type, Class<@NotNull T> clazz) {
        EntLibCryptoStrategy algorithm = ALG_REGISTRY.get(type);
        if (clazz.isInstance(algorithm))
            return clazz.cast(algorithm);
        throw new UnsupportedOperationException("Not supported: " + clazz.getSimpleName());
    }

    /**
     * 지정된 알고리즘 타입에 해당하는 키 스트레티지를 반환하는 메소드입니다.
     *
     * @param type  알고리즘 타입
     * @param clazz 반환받을 키 스트레티지 클래스 타입
     * @param <T>   키 스트레티지 타입
     * @return 해당 타입의 키 스트레티지
     * @throws UnsupportedOperationException 지원하지 않는 타입인 경우
     */
    public static <T extends EntLibKey> T getKeyStrategy(@NotNull EntLibAlgorithmType type, Class<@NotNull T> clazz) {
        EntLibKey algorithm = KEY_REGISTRY.get(type);
        if (clazz.isInstance(algorithm))
            return clazz.cast(algorithm);
        throw new UnsupportedOperationException("Not supported: " + clazz.getSimpleName());
    }

    /**
     * 등록된 모든 스트레티지의 수를 반환하는 메소드입니다.
     *
     * @return 등록된 스트레티지 수
     */
    public static int registeredCount() {
        return ALG_REGISTRY.size() + KEY_REGISTRY.size();
    }

    /**
     * 지정된 알고리즘 타입이 등록되어 있는지 확인하는 메소드입니다.
     *
     * @param type 확인할 알고리즘 타입
     * @return 등록되어 있으면 {@code true}, 아니면 {@code false}
     */
    public static boolean isAlgRegistered(@NotNull EntLibAlgorithmType type) {
        return ALG_REGISTRY.containsKey(type);
    }

    /**
     * 지정된 키 알고리즘 타입이 등록되어 있는지 확인하는 메소드입니다.
     *
     * @param type 확인할 키 알고리즘 타입
     * @return 등록되어 있으면 {@code true}, 아니면 {@code false}
     */
    public static boolean isKeyRegistered(@NotNull EntLibAlgorithmType type) {
        return KEY_REGISTRY.containsKey(type);
    }

}
