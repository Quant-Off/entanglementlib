/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib;

import lombok.extern.slf4j.Slf4j;

import java.lang.foreign.Arena;
import java.util.Locale;

@Slf4j
public final class HeuristicArenaFactory {

    /// 사용자가 코드 레벨에서 설정을 강제할 수 있는 전역 변수입니다.
    private static volatile ArenaMode GLOBAL_MODE = ArenaMode.AUTO;

    public enum ArenaMode {
        /// 오직 현재 스레드만 접근 가능 (보안성 최상, 단일 스레드 환경)
        CONFINED,
        /// 모든 스레드에서 접근 가능 (유연성 최상, 비동기 서버 환경)
        SHARED,
        /// 환경을 감지하여 자동으로 결정
        AUTO
    }

    /// 사용자가 전역 Arena 모드를 강제로 설정할 수 있도록 하는 메소드입니다.
    /// 앱 시작 시점에 호출하는 것이 권장됩니다.
    ///
    /// @param mode Arena 모드
    public static void setGlobalArenaMode(ArenaMode mode) {
        GLOBAL_MODE = mode;
        log.info("얽힘 라이브러리 전역 Arena 모드가 '{}'로 설정되었습니다.", mode);
    }

    /// 환경에 맞는 최적의 Arena를 생성하여 반환합니다.
    ///
    /// @return 환경에 맞는 Arena
    public static Arena intelligenceCreateArena() {
        ArenaMode mode = GLOBAL_MODE;

        if (mode == ArenaMode.AUTO) {
            mode = determineModeFromSystemProperty();
        }

        return switch (mode) {
            case SHARED -> Arena.ofShared();
            case CONFINED -> Arena.ofConfined();
            default -> Arena.ofConfined(); // Fallback
        };
    }

    /// JVM 시스템 속성 및 클래스패스를 분석하여 모드를 결정하는 메소드입니다.
    ///
    /// @return 시스템 속성 또는 클래스패스에 따라 결정된 Arena 모드
    private static ArenaMode determineModeFromSystemProperty() {
        String sysProp = System.getProperty("entanglement.arena.mode");
        if (sysProp != null) {
            try {
                log.debug("얽힘 라이브러리 전역 Arena 모드가 VM옵션대로 '{}'로 설정되었습니다.", sysProp.toUpperCase(Locale.ROOT));
                return ArenaMode.valueOf(sysProp.toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                log.warn("'{}'은(는) 잘못된 시스템 속성 값입니다.", sysProp);
            }
        }

        // 휴리스틱 비동기/서버 프레임워크 감지
        if (isClassPresent("io.netty.channel.EventLoop") || // Netty
                isClassPresent("org.springframework.boot.SpringApplication") || // Spring Boot
                isClassPresent("org.apache.catalina.startup.Tomcat") || // Tomcat
                isClassPresent("reactor.core.publisher.Flux")) { // Project Reactor
            log.debug("비동기/서버 환경이 감지되었습니다. SHARED 모드를 강제합니다.");
            return ArenaMode.SHARED;
        }

        return ArenaMode.CONFINED;
    }

    private static boolean isClassPresent(String className) {
        try {
            Class.forName(className, false, HeuristicArenaFactory.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }
}