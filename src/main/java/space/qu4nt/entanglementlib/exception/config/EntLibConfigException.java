/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.config;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.exception.EntanglementLibException;

/**
 * 얽힘 라이브러리의 구성 파일 관련 작업 중 발생 가능한 예외 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public class EntLibConfigException extends EntanglementLibException {

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
    public <T> EntLibConfigException(Class<T> clazz, @NotNull String fullKey, @NotNull Throwable cause) {
        super(clazz, fullKey, cause);
    }

}
