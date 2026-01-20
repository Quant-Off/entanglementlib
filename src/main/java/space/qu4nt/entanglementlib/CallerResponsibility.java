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

package space.qu4nt.entanglementlib;

import java.lang.annotation.ElementType;
import java.lang.annotation.Target;

/**
 * 보안적 책임은 호출자에게 있음을 알리는 어노테이션입니다.
 * 호출자가 해당 어노테이션이 사용된 멤버 사용 시, 작업 종료 후
 * 반드시 보안 작업이 필요함을 의미합니다.
 * <p>
 * 예를 들어, 이 어노테이션이 (복사본이 아닌) 원본 데이터를 반환하는 메소드에 사용되었고
 * 해당 메소드를 사용하고자 하는 경우 반환받은 데이터를 소거해야 합니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Target(ElementType.TYPE_USE)
public @interface CallerResponsibility {

    /**
     * 책임 전가의 사유 또는 설명를 정의합니다.
     *
     * @return 책임 전가 사유 또는 설명
     */
    String value() default "";

}
