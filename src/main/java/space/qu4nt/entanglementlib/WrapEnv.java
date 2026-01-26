/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.exception.critical.EntLibEnvError;
import space.qu4nt.entanglementlib.util.StringUtil;

import java.util.Optional;

/**
 * {@code EntanglementLib}에서 사용되는 환경 변수를 래핑하는 추상 클래스입니다.
 * <p>
 * 이 라이브러리의 환경 변수는 이 클래스의 인스턴스를 통해 호출이 이루어져야 합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Getter(AccessLevel.PACKAGE)
@Setter(AccessLevel.PACKAGE)
@NoArgsConstructor
sealed abstract class WrapEnv permits EntanglementLibEnvs {

    String env;
    boolean req;

    /**
     * 해당 환경변수 값의 {@code req} 필드가 {@code true}인 경우
     * 그 값은 {@code null}이면 안 됩니다. 이 메소드는 이러한 경우를 체크합니다.
     * <p>
     * 해당 환경 변수의 기본값이 할당되어 있으며 {@code req} 필드가 {@code false}인 경우,
     * 할당된 기본값을 반환합니다.
     *
     * @param env 타겟 환경 변수
     * @param req 필수 여부
     * @param def 필수가 아니며 타겟 환경 변수가 {@code null}인 경우 반환값
     */
    WrapEnv(@NotNull String env, boolean req, @Nullable String def) {
        env = StringUtil.toUpperCase(env);
        Optional<String> opt = Optional.ofNullable(System.getenv(env));
        if (opt.isPresent()) {
            this.env = opt.get();
        } else {
            if (req) error(env);
            if (def == null) error(env);
            this.env = def;
        }
        this.req = req;
    }

    /**
     * 런타임 예외를 발생시키는 메소드입니다.
     *
     * @param env 예외에 보여질 누락된 환경 변수 이름
     */
    static void error(String env) {
        throw new EntLibEnvError(env);
    }
}
