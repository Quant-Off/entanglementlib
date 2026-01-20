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

package space.qu4nt.entanglementlib.exception;

/**
 * 환경 변수를 정의하지 않았거나, 사용되는 도중 예외가 발생할 수 있습니다.
 * <p>
 * 해당 예외 클래스는 {@code i18n} 국제화 리소스 로드 전에만 사용되어
 * 언어 기능을 지원하지 않습니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public class EntanglementLibNoSuchEnvException extends RuntimeException {

    /**
     * 환경 변수를 찾을 수 없습니다.
     *
     * @param envName 환경 변수명
     */
    public EntanglementLibNoSuchEnvException(String envName) {
        super("No Such environment variable: " + envName);
    }

}
