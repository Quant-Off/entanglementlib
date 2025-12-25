/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource.language;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.resource.ResourceCaller;
import space.qu4nt.entanglementlib.resource.SupportedFormat;

import java.nio.charset.StandardCharsets;
import java.util.ResourceBundle;

import static space.qu4nt.entanglementlib.util.StringUtil.placeholderFormat;

/**
 * 다양한 국적의 언어를 간편하게 사용하기 위한 클래스입니다.
 * <p>
 * 언어 파일은 멀티 모듈 프로젝트가 아닌 경우 다음의 형식으로 저장됩니다.
 * <pre>
 * class-SomeClass:
 *   msg-field: "Hello, World!"
 *   ...
 * </pre>
 * 멀티 모듈 프로젝트의 경우 다음의 형식으로 저장됩니다.
 * <pre>
 * module-a:
 *   class-SomeClass:
 *     msg-field: "Hello, Multi-World!"
 * </pre>
 * 이 경우 키 호출 양식을 주의하세요.
 * <p>
 * 언어 파일은 {@code .yml} 또는 {@code .yaml} 형식으로 저장되며,
 * {@code messages_<locale>} 이름을 유지하세요. <i>locale</i> 플레이스 홀더는
 * <a href="https://wikipedia.org/wiki/ISO_3166-1">ISO 3166-1</a> 에 따른 국가 코드,
 * <a href="https://en.wikipedia.org/wiki/List_of_ISO_639_language_codes">ISO 639-1</a>
 * 에 따른 언어 코드 양식을 준수하세요.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public final class Language {

    // MSG

    /**
     * 공용 리소스에서 입력받은 언어의 메시지 파일 속 메시지 키에 할당된 메시지를
     * 반환하는 메소드입니다.
     *
     * @param language 사용 가능한 언어 중 가져오고자 하는 언어 {@link SupportedLanguage}
     * @param key      메시지 파일 속 참조할 메시지의 키
     * @param def      메시지 파일 속 참조할 메시지의 키가 존재하지 않은 경우 반환할 메시지
     * @return 할당된 메시지
     */
    public static String msg(final SupportedLanguage language, String key, @NotNull String def) {
        final ResourceBundle bundle = ResourceCaller
                .getCustomResourceInPublicInnerDir(SupportedFormat.YAML, "lang", language.getFilename(), StandardCharsets.UTF_8);
        return msg(bundle, key, def);
    }

    /**
     * 공용 리소스에서 입력받은 언어의 메시지 파일 속 메시지 키에 할당된 메시지를
     * 반환하는 메소드입니다. 키를 찾을 수 없는 경우, 키 경로가 표시됩니다.
     *
     * @param language 사용 가능한 언어 중 가져오고자 하는 언어 {@link SupportedLanguage}
     * @param key      메시지 파일 속 참조할 메시지의 키
     * @return 할당된 메시지, 찾을 수 없는 경우 키 경로 문자열
     */
    public static String msg(final SupportedLanguage language, String key) {
        return msg(language, key, key);
    }

    /**
     * 공용 리소스에서 설정된 기본 언어의 메시지 파일 속 메시지 키에 할당된 메시지를
     * 반환하는 메소드입니다. 만약 기본 언어를 세팅하지 않은 경우 {@code ENTANGLEMENT_DEFAULT_LANG}
     * 환경 변수에 할당된 언어를 불러옵니다.
     *
     * @param key 메시지 파일 속 참조할 메시지의 키
     * @param def 메시지 파일 속 참조할 메시지의 키가 존재하지 않은 경우 반환할 메시지
     * @return 할당된 메시지
     */
    public static String msg(@NotNull String key, @NotNull String def) {
        return msg(InternalFactory.getPublicConfig().getLanguage(),
                key, def);
    }

    /**
     * 공용 리소스에서 설정된 기본 언어의 메시지 파일 속 메시지 키에 할당된 메시지를
     * 반환하는 메소드입니다. 만약 기본 언어를 세팅하지 않은 경우 {@code ENTANGLEMENT_DEFAULT_LANG}
     * 환경 변수에 할당된 언어를 불러옵니다. 키를 찾을 수 없는 경우, 키 경로가 표시됩니다.
     *
     * @param key 메시지 파일 속 참조할 메시지의 키
     * @return 할당된 메시지
     */
    public static String msg(@NotNull String key) {
        return msg(InternalFactory.getPublicConfig().getLanguage(),
                key, key);
    }

    /**
     * 입력받은 리소스 번들에서 메시지 키에 할당된 메시지를 반환하는 메소드입니다.
     *
     * @param bundle 리소스 번들
     * @param key    메시지 파일 속 참조할 메시지의 키
     * @param def    메시지 파일 속 참조할 메시지의 키가 존재하지 않은 경우 반환할 메시지
     * @return 할당된 메시지
     */
    public static String msg(@NotNull ResourceBundle bundle, String key, @NotNull String def) {
        if (bundle.containsKey(key))
            return bundle.getString(key);
        return def;
    }

    /**
     * 입력받은 리소스 번들에서 메시지 키에 할당된 메시지를 반환하는 메소드입니다.
     * 키를 찾을 수 없는 경우, 키 경로가 표시됩니다.
     *
     * @param bundle 리소스 번들
     * @param key    메시지 파일 속 참조할 메시지의 키
     * @return 할당된 메시지, 찾을 수 없는 경우 키 경로 문자열
     */
    public static String msg(@NotNull ResourceBundle bundle, String key) {
        return msg(bundle, key, key);
    }

    // ARGS

    /**
     * 공용 리소스에서 입력받은 언어의 메시지 파일 속 메시지 키에 할당된 메시지(raw)를
     * 호출하여 플레이스홀더를 변환하여 반환하는 메소드입니다.
     *
     * @param language 사용 가능한 언어 중 가져오고자 하는 언어 {@link SupportedLanguage}
     * @param key      메시지 파일 속 참조할 메시지의 키
     * @param def      메시지 파일 속 참조할 메시지의 키가 존재하지 않은 경우 반환할 메시지
     * @param args     플레이스홀더 변경 인자
     * @return 할당 후 변환된 메시지
     */
    public static String args(final SupportedLanguage language, String key, @NotNull String def, Object... args) {
        // 기존 메소드를 호출하여 raw 메시지 가져오기
        String message = msg(language, key, def);
        if (args == null || args.length == 0)
            return message; // 인자가 없으면 그대로 반환
        return placeholderFormat(message, args);
    }

    /**
     * 공용 리소스에서 입력받은 언어의 메시지 파일 속 메시지 키에 할당된 메시지(raw)를
     * 호출하여 플레이스홀더를 변환하여 반환하는 메소드입니다. 키를 찾을 수 없는 경우,
     * 키 경로가 표시됩니다.
     *
     * @param language 사용 가능한 언어 중 가져오고자 하는 언어 {@link SupportedLanguage}
     * @param key      메시지 파일 속 참조할 메시지의 키
     * @param args     플레이스홀더 변경 인자
     * @return 할당 후 변환된 메시지, 키를 찾을 수 없는 경우 키 경로 문자열
     */
    public static String args(final SupportedLanguage language, String key, Object... args) {
        return args(language, key, key, args);
    }

    /**
     * 공용 리소스에서 입력받은 언어의 메시지 파일 속 메시지 키에 할당된 메시지(raw)를 호출하여 플레이스홀더를
     * 변환하여 반환하는 메소드입니다. 만약 기본 언어를 세팅하지 않은 경우 {@code ENTANGLEMENT_DEFAULT_LANG}
     * 환경 변수에 할당된 언어를 불러옵니다.
     *
     * @param key  메시지 파일 속 참조할 메시지의 키
     * @param def  메시지 파일 속 참조할 메시지의 키가 존재하지 않은 경우 반환할 메시지
     * @param args 플레이스홀더 변경 인자
     * @return 할당된 메시지
     */
    public static String args(@NotNull String key, @NotNull String def, Object... args) {
        return args(InternalFactory.getPublicConfig().getLanguage(),
                key, def, args);
    }

    /**
     * 공용 리소스에서 입력받은 언어의 메시지 파일 속 메시지 키에 할당된 메시지(raw)를 호출하여 플레이스홀더를
     * 변환하여 반환하는 메소드입니다. 만약 기본 언어를 세팅하지 않은 경우 {@code ENTANGLEMENT_DEFAULT_LANG}
     * 환경 변수에 할당된 언어를 불러옵니다. 키를 찾을 수 없는 경우, 키 경로가 표시됩니다.
     *
     * @param key  메시지 파일 속 참조할 메시지의 키
     * @param args 플레이스홀더 변경 인자
     * @return 할당된 메시지
     */
    public static String args(@NotNull String key, Object... args) {
        return args(InternalFactory.getPublicConfig().getLanguage(),
                key, args);
    }

    /**
     * 입력받은 리소스 번들에서 메시지 키에 할당된 메시지(raw)를 호출하여 플레이스홀더를
     * 변환하여 반환하는 메소드입니다.
     *
     * @param bundle 리소스 번들
     * @param key    메시지 파일 속 참조할 메시지의 키
     * @param def    메시지 파일 속 참조할 메시지의 키가 존재하지 않은 경우 반환할 메시지
     * @param args   플레이스홀더 변경 인자
     * @return 할당 후 변환된 메시지
     */
    public static String args(@NotNull ResourceBundle bundle, String key, @NotNull String def, Object... args) {
        String message = msg(bundle, key, def);
        if (args == null || args.length == 0)
            return message;
        return placeholderFormat(message, args);
    }

    /**
     * 입력받은 리소스 번들에서 메시지 키에 할당된 메시지(raw)를 호출하여 플레이스홀더를
     * 변환하여 반환하는 메소드입니다. 키를 찾을 수 없는 경우, 키 경로가 표시됩니다.
     *
     * @param bundle 리소스 번들
     * @param key    메시지 파일 속 참조할 메시지의 키
     * @param args   플레이스홀더 변경 인자
     * @return 할당 후 변환된 메시지, 키를 찾을 수 없는 경우 키 경로 문자열
     */
    public static String args(@NotNull ResourceBundle bundle, String key, Object... args) {
        return args(bundle, key, key, args);
    }

    // THROW

    /**
     * 공용 리소스에서 입력받은 언어의 메시지 파일 속 메시지 키에 할당된 메시지(raw)를 호출하여 예외와
     * 플레이스 홀더를 변환하여 반환하는 메소드입니다.
     *
     * @param language 사용 가능한 언어 중 가져오고자 하는 언어 {@link SupportedLanguage}
     * @param key      메시지 파일 속 참조할 메시지의 키
     * @param def      메시지 파일 속 참조할 메시지의 키가 존재하지 않은 경우 반환할 메시지
     * @param args     플레이스홀더 변경 인자
     * @return 할당 후 변환된 메시지
     */
    public static String thr(final SupportedLanguage language, String key, @NotNull String def, @NotNull Throwable cause, Object... args) {
        String message = args(language, key, def, args);
        // 예외 메시지 추가
        if (cause != null) {
            String causeMessage = cause.getMessage();
            if (causeMessage == null) {
                causeMessage = "unknown error";
            }
            message += " : " + causeMessage;
        }
        return message;
    }

    /**
     * 공용 리소스에서 입력받은 언어의 메시지 파일 속 메시지 키에 할당된 메시지(raw)를 호출하여 예외와
     * 플레이스 홀더를 변환하여 반환하는 메소드입니다. 키를 찾을 수 없는 경우, 키 경로가 표시됩니다.
     *
     * @param language 사용 가능한 언어 중 가져오고자 하는 언어 {@link SupportedLanguage}
     * @param key      메시지 파일 속 참조할 메시지의 키
     * @param args     플레이스홀더 변경 인자
     * @return 할당 후 변환된 메시지, 키를 찾을 수 없는 경우 키 경로 문자열
     */
    public static String thr(final SupportedLanguage language, String key, @NotNull Throwable cause, Object... args) {
        return thr(language, key, key, cause, args);
    }

    /**
     * 공용 리소스에서 입력받은 언어의 메시지 파일 속 메시지 키에 할당된 메시지(raw)를 호출하여 예외와
     * 플레이스 홀더를 변환하여 반환하는 메소드입니다. 만약 기본 언어를 세팅하지 않은 경우 {@code ENTANGLEMENT_DEFAULT_LANG}
     * 환경 변수에 할당된 언어를 불러옵니다.
     *
     * @param key  메시지 파일 속 참조할 메시지의 키
     * @param def  메시지 파일 속 참조할 메시지의 키가 존재하지 않은 경우 반환할 메시지
     * @param args 플레이스홀더 변경 인자
     * @return 할당된 메시지
     */
    public static String thr(@NotNull String key, @NotNull String def, @NotNull Throwable cause, Object... args) {
        return thr(InternalFactory.getPublicConfig().getLanguage(),
                key, def, cause, args);
    }

    /**
     * 공용 리소스에서 입력받은 언어의 메시지 파일 속 메시지 키에 할당된 메시지(raw)를 호출하여 예외와
     * 플레이스 홀더를 변환하여 반환하는 메소드입니다. 만약 기본 언어를 세팅하지 않은 경우 {@code ENTANGLEMENT_DEFAULT_LANG}
     * 환경 변수에 할당된 언어를 불러옵니다. 키를 찾을 수 없는 경우, 키 경로가 표시됩니다.
     *
     * @param key  메시지 파일 속 참조할 메시지의 키
     * @param args 플레이스홀더 변경 인자
     * @return 할당된 메시지
     */
    public static String thr(@NotNull String key, @NotNull Throwable cause, Object... args) {
        return thr(InternalFactory.getPublicConfig().getLanguage(),
                key, cause, args);
    }

    /**
     * 입력받은 리소스 번들에서 메시지 키에 할당된 메시지(raw)를 호출하여 예외와
     * 플레이스 홀더를 변환하여 반환하는 메소드입니다.
     *
     * @param bundle 리소스 번들
     * @param key    메시지 파일 속 참조할 메시지의 키
     * @param def    메시지 파일 속 참조할 메시지의 키가 존재하지 않은 경우 반환할 메시지
     * @param cause  예외
     * @param args   플레이스홀더 변경 인자
     * @return 할당 후 변환된 메시지
     */
    public static String thr(@NotNull ResourceBundle bundle, String key, @NotNull String def, @NotNull Throwable cause, Object... args) {
        String message = args(bundle, key, def, args);
        // 예외 메시지 추가
        if (cause != null) {
            String causeMessage = cause.getMessage();
            if (causeMessage == null) {
                causeMessage = "unknown error";
            }
            message += " : " + causeMessage;
        }
        return message;
    }

    /**
     * 입력받은 리소스 번들에서 메시지 키에 할당된 메시지(raw)를 호출하여 예외와
     * 플레이스 홀더를 변환하여 반환하는 메소드입니다. 키를 찾을 수 없는 경우, 키 경로가 표시됩니다.
     *
     * @param bundle 리소스 번들
     * @param key    메시지 파일 속 참조할 메시지의 키
     * @param cause  예외
     * @param args   플레이스홀더 변경 인자
     * @return 할당 후 변환된 메시지, 키를 찾을 수 없는 경우 키 경로 문자열
     */
    public static String thr(@NotNull ResourceBundle bundle, String key, @NotNull Throwable cause, Object... args) {
        return thr(bundle, key, key, cause, args);
    }

}
