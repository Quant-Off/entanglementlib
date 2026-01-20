/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
     * 현재 암호화 서비스의 방식(형식)을 배열로 반환하는 메소드입니다.
     *
     * @return 알고리즘 방식 배열
     */
    CryptoMethod[] getCryptoMethod();

    /**
     * 얽힘 라이브러리에서 지원하는 모든 암호화 및 서명 알고리즘은
     * 평문 바이트 배열을 가집니다. 해당 메소드는 방어적 복사를 통해
     * 평분 바이트 배열을 안전하게 호출합니다.
     *
     * @return 안전하게 복사된 평문 바이트 배열
     */
    @Deprecated
    default byte @NotNull [] getPlainBytes() {
        return new byte[1];
    }

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
