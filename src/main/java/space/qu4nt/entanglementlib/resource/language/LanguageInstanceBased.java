/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource.language;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

/**
 * 언어를 좀 더 간편하게 사용할 수 있도록 상수로써 선언할 수 있도록 해주는 클래스입니다.
 * 특정 클래스에서 {@link Language} 클래스를 통한 언어 호출이 잦은 경우 유용합니다.
 * <p>
 * 이 클래스에선 {@code ENTANGLEMENT_DEFAULT_LANG} 환경 변수를 기반으로 동작합니다.
 *
 * @author Q. T. Felix
 * @see Language 기반 언어 클래스
 * @since 1.0.0
 */
@Getter
public class LanguageInstanceBased<T> {

    private Class<?> clazz;

    private LanguageInstanceBased(Class<T> clazz) {
        this.clazz = clazz;
    }

    public static <T> LanguageInstanceBased<T> create(Class<T> clazz) {
        return new LanguageInstanceBased<>(clazz);
    }

    public LanguageInstanceBased<T> setClass(Class<?> clazz) {
        this.clazz = clazz;
        return this;
    }

    public String msg(@Nullable String topKey, String lowKey) {
        Objects.requireNonNull(lowKey);
        return Language.msg(fixTopKey(topKey) + lowKey);
    }

    public String msg(String lowKey) {
        Objects.requireNonNull(lowKey);
        return msg(null, clazz.getSimpleName() + "." + lowKey);
    }

    public String args(@Nullable String topKey, String lowKey, Object... args) {
        Objects.requireNonNull(lowKey);
        return Language.args(fixTopKey(topKey) + lowKey, args);
    }

    public String argsNonTopKey(String lowKey, Object... args) {
        Objects.requireNonNull(lowKey);
        return args(null, clazz.getSimpleName() + "." + lowKey, args);
    }

    public String thr(@Nullable String topKey, String lowKey, @NotNull Throwable cause, Object... args) {
        Objects.requireNonNull(lowKey);
        return Language.thr(fixTopKey(topKey) + lowKey, cause, args);
    }

    public String thr(String lowKey, @NotNull Throwable cause, Object... args) {
        Objects.requireNonNull(lowKey);
        return thr(null, clazz.getSimpleName() + "." + lowKey, cause, args);
    }

    private String fixTopKey(String topKey) {
        return topKey == null ? "class-" : (topKey + ".class-");
    }

}
