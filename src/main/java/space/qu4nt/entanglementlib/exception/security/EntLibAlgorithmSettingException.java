/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.security;

import org.jetbrains.annotations.NotNull;

/**
 * 세부 알고리즘을 사용하여 암호화 작업을 진행할 때,
 * 평문, 매개변수 등의 세팅 중 발생 가능한 예외 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public class EntLibAlgorithmSettingException extends EntLibSecurityException {

    /**
     * 언어 파일의 특정 키를 받아 메시지를 출력합니다.
     * <p>
     * 클래스 매개변수는 메시지 구역을 식별하기 위한 키입니다.
     *
     * @param clazz   메시지 구역 식별 클래스
     * @param fullKey 메시지 키
     */
    public <T> EntLibAlgorithmSettingException(Class<T> clazz, @NotNull String fullKey) {
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
    public <T> EntLibAlgorithmSettingException(Class<T> clazz, @NotNull String fullKey, Object... args) {
        super(clazz, fullKey, args);
    }
}
