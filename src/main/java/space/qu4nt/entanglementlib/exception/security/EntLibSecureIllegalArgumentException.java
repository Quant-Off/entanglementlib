/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.security;

import org.jetbrains.annotations.NotNull;

/**
 * {@code EntanglementLib}의 기능 중 특정 부분에서 불법적이거나 부적절한 시간에
 * 작업이 수행되었을 경우에 사용되는 예외 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public class EntLibSecureIllegalArgumentException extends EntLibSecurityException {

    /**
     * 언어 파일의 특정 키를 받아 메시지를 출력합니다.
     * <p>
     * 클래스 매개변수는 메시지 구역을 식별하기 위한 키입니다.
     *
     * @param clazz   메시지 구역 식별 클래스
     * @param fullKey 메시지 키
     */
    public <T> EntLibSecureIllegalArgumentException(Class<T> clazz, @NotNull String fullKey) {
        super(clazz, fullKey);
    }
}
