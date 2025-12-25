/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource.language;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;
import java.util.ResourceBundle;

/**
 * 언어를 좀 더 간편하게 사용할 수 있도록 상수로써 선언할 수 있도록 해주는 클래스입니다.
 * 특정 클래스에서 {@link Language} 클래스를 통한 언어 호출이 잦은 경우 유용합니다.
 * <p>
 * 이 클래스에선 {@code ENTANGLEMENT_DEFAULT_LANG} 환경 변수를 기반으로 동작합니다.
 *
 * @param <T> 바인딩 타겟 타입 파라미터
 * @author Q. T. Felix
 * @see Language 기반 언어 클래스
 * @since 1.0.0
 */
@Getter
public class LanguageInstanceBased<T> {

    private Class<?> clazz;
    /**
     * 이 변수는 {@code null}일 수 있지만,
     * null이 아닌 경우 우선적으로 사용됩니다.
     */
    @Nullable
    private final ResourceBundle bundle;

    private LanguageInstanceBased(Class<T> clazz) {
        this.clazz = clazz;
        this.bundle = null;
    }

    private LanguageInstanceBased(@NotNull ResourceBundle bundle, Class<T> clazz) {
        this.clazz = clazz;
        this.bundle = bundle;
    }

    public static <T> LanguageInstanceBased<T> create(Class<T> clazz) {
        return new LanguageInstanceBased<>(clazz);
    }

    /**
     * 전달받은 리소스 번들에서 언어 파일을 로드하기 위한 메소드입니다.
     * <p>
     * 얽힘 라이브러리를 외부에서 사용하는 경우 이 라이브러리에 포함된 메시지 키를 사용하지 않고
     * 호출자 프로젝트에서 언어 파일을 새롭게 로드하고자 하는 경우 사용됩니다.
     *
     * @param bundle 리소스 번들
     * @param clazz  언어 파일에서 바인딩할 타입
     * @param <T>    바인딩 타겟 타입 파라미터
     * @return 언어 인스턴스 {@link LanguageInstanceBased}
     */
    public static <T> LanguageInstanceBased<T> create(@NotNull ResourceBundle bundle, Class<T> clazz) {
        return new LanguageInstanceBased<>(bundle, clazz);
    }

    public LanguageInstanceBased<T> setClass(Class<?> clazz) {
        this.clazz = clazz;
        return this;
    }

    public String msg(@Nullable String topKey, String lowKey) {
        Objects.requireNonNull(lowKey);
        String key = fixTopKey(topKey) + lowKey;
        if (bundle != null) {
            return Language.msg(bundle, key);
        }
        return Language.msg(key);
    }

    public String msg(String lowKey) {
        Objects.requireNonNull(lowKey);
        return msg(null, clazz.getSimpleName() + "." + lowKey);
    }

    public String args(@Nullable String topKey, String lowKey, Object... args) {
        Objects.requireNonNull(lowKey);
        String key = fixTopKey(topKey) + lowKey;
        if (bundle != null) {
            return Language.args(bundle, key, args);
        }
        return Language.args(key, args);
    }

    public String argsNonTopKey(String lowKey, Object... args) {
        Objects.requireNonNull(lowKey);
        return args(null, clazz.getSimpleName() + "." + lowKey, args);
    }

    public String thr(@Nullable String topKey, String lowKey, @NotNull Throwable cause, Object... args) {
        Objects.requireNonNull(lowKey);
        String key = fixTopKey(topKey) + lowKey;
        if (bundle != null) {
            return Language.thr(bundle, key, cause, args);
        }
        return Language.thr(key, cause, args);
    }

    public String thr(String lowKey, @NotNull Throwable cause, Object... args) {
        Objects.requireNonNull(lowKey);
        return thr(null, clazz.getSimpleName() + "." + lowKey, cause, args);
    }

    private String fixTopKey(String topKey) {
        return topKey == null ? "class-" : (topKey + ".class-");
    }

}
