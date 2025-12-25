/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.security.EntLibParameterSpec;

/**
 * 얽힘 라이브러리 내 모든 암호화 서비스의 공통 기반 인터페이스입니다.
 * <p>
 * 이 인터페이스는 모든 암호화 서비스가 공통적으로 가져야 할 기능을 정의하며,
 * 특히 {@link AutoCloseable}을 상속받아 리소스 관리를 용이하게 합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public interface EntLibCryptoService extends AutoCloseable {

    /**
     * 얽힘 라이브러리에서 지원하는 모든 암호화 및 서명 알고리즘은
     * 평문 바이트 배열을 가집니다. 해당 메소드는 방어적 복사를 통해
     * 평분 바이트 배열을 안전하게 호출합니다.
     *
     * @return 안전하게 복사된 평문 바이트 배열
     */
    byte @NotNull [] getPlainBytes();

    /**
     * 현재 암호화 서비스의 매개변수 사양을 반환합니다.
     * <p>
     * 이 메소드는 서비스가 사용하는 알고리즘, 키 크기, 모드, 패딩 등
     * 구체적인 암호화 설정 정보를 제공합니다.
     *
     * @return 현재 암호화 서비스의 {@link EntLibParameterSpec} 객체
     */
    EntLibParameterSpec getType();
}
