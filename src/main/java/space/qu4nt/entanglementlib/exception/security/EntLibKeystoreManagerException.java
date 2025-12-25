/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.security;

import org.jetbrains.annotations.NotNull;

public class EntLibKeystoreManagerException extends EntLibSecurityException {
    /**
     * 전달받은 예외 메시지를 사용하여 예외를 발생시킵니다.
     *
     * @param message 예외 메시지
     */
    public EntLibKeystoreManagerException(String message) {
        super(message);
    }

    /**
     * 언어 파일의 특정 키를 받아 메시지를 출력합니다.
     * <p>
     * 클래스 매개변수는 메시지 구역을 식별하기 위한 키입니다.
     *
     * @param clazz   메시지 구역 식별 클래스
     * @param fullKey 메시지 키
     */
    public <T> EntLibKeystoreManagerException(Class<T> clazz, @NotNull String fullKey) {
        super(clazz, fullKey);
    }

    /**
     * 언어 파일의 특정 키를 받아 메시지를 출력합니다.
     * 가변 변수를 받아 {@code {}} 플레이스홀더를 변수로 처리합니다.
     * <p>
     * 클래스 매개변수는 메시지 구역을 식별하기 위한 키입니다.
     *
     * @param clazz   메시지 구역 식별 클래스
     * @param fullKey 메시지 키
     * @param args    플레이스홀더 변경 인자
     */
    public <T> EntLibKeystoreManagerException(Class<T> clazz, @NotNull String fullKey, Object... args) {
        super(clazz, fullKey, args);
    }

    /**
     * 언어 파일의 특정 키를 받아 예외와 함께 메시지를 출력합니다.
     * 예외 정보가 포함되어야 하는 경우에 사용됩니다.
     * <p>
     * 클래스 매개변수는 메시지 구역을 식별하기 위한 키입니다.
     *
     * @param clazz   메시지 구역 식별 클래스
     * @param fullKey 메시지 키
     * @param cause   발생한 예외
     */
    public <T> EntLibKeystoreManagerException(Class<T> clazz, @NotNull String fullKey, @NotNull Throwable cause) {
        super(clazz, fullKey, cause);
    }
}
