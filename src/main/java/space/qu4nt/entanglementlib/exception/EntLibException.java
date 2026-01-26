/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;

import java.io.Serial;

/// 얽힘 라이브러리 전반에서 사용되는 기본 예외 클래스입니다.
///
/// 이 클래스는 [Exception]을 상속받으며, [LanguageInstanceBased]를 사용하여
/// 다국어 메시지 처리를 지원합니다.
///
/// 이 클래스는 기본적으로 `Checked Exception`입니다. 확장하여 다양한 상황에 대해
/// 예외 처리가 가능합니다.
///
/// @author Q. T. Felix
/// @since 1.1.0
public class EntLibException extends Exception {

    @Serial
    private static final long serialVersionUID = 2378593800480779310L;

    /**
     * 새로운 {@link EntLibException} 인스턴스를 생성하는 기본 생성자 메소드입니다.
     */
    public EntLibException() {
        super();
    }

    /**
     * 다국어 처리가 필요하지 않은 경우 이 인스턴스를 사용할 수 있습니다.
     *
     * @param message 메시지
     */
    public EntLibException(String message) {
        super(message);
    }

    /**
     * 발생한 예외만 넘기기 위해 이 인스턴스를 사용할 수 있습니다.
     *
     * @param cause 발생 예외
     */
    public EntLibException(Throwable cause) {
        super(cause);
    }

    /// 다국어 처리가 필요하지 않으며, 발생한 예외를 넘기기 위해 이
    /// 인스턴스를 사용할 수 있습니다.
    ///
    /// @param message 메시지
    /// @param cause   발생 예외
    public EntLibException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * 지정된 클래스와 메시지 키를 사용하여 새로운 {@link EntLibException} 인스턴스를 생성하는 메소드입니다.
     * <p>
     * {@link LanguageInstanceBased}를 통해 해당 클래스에 맞는 다국어 메시지를 조회합니다.
     *
     * @param i18nTargetClass 다국어 메시지 리소스를 조회할 대상 클래스
     * @param key             메시지 키 ({@code null}이 아니어야 함)
     * @param <T>             대상 클래스의 타입
     */
    public <T> EntLibException(Class<T> i18nTargetClass, @NotNull String key) {
        super(LanguageInstanceBased.create(i18nTargetClass).msg(key));
    }

    /**
     * 지정된 클래스, 메시지 키, 그리고 원인 예외를 사용하여 새로운 {@link EntLibException} 인스턴스를 생성하는 메소드입니다.
     *
     * @param i18nTargetClass 다국어 메시지 리소스를 조회할 대상 클래스
     * @param key             메시지 키 ({@code null}이 아니어야 함)
     * @param cause           이 예외가 발생하게 된 원인 예외
     * @param <T>             대상 클래스의 타입
     */
    public <T> EntLibException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause) {
        super(LanguageInstanceBased.create(i18nTargetClass).thr(key, cause));
    }

    /**
     * 지정된 클래스, 메시지 키, 원인 예외, 그리고 포맷팅 인자들을 사용하여 새로운 {@link EntLibException} 인스턴스를 생성하는 메소드입니다.
     *
     * @param i18nTargetClass 다국어 메시지 리소스를 조회할 대상 클래스
     * @param key             메시지 키 ({@code null}이 아니어야 함)
     * @param cause           이 예외가 발생하게 된 원인 예외
     * @param args            메시지 포맷팅에 사용될 인자들
     * @param <T>             대상 클래스의 타입
     */
    public <T> EntLibException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause, Object... args) {
        super(LanguageInstanceBased.create(i18nTargetClass).thr(key, cause, args));
    }
}
