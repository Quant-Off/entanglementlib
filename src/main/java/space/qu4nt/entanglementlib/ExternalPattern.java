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
 * 반드시 외부에서만 사용됨을 알리는 마커 어노테이션입니다.
 * {@link InternalFactory} 객체 부트스트랩 시, 내부(internal)에서 사용되는 멤버와
 * 외부(external)에서 사용되는 멤버는 다르다는 것을 명확히 하기 위해 사용됩니다.
 * <p>
 * 이 어노테이션은 타입 레벨에 사용하지 마세요. 혼동이 생길 수 있습니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Target(ElementType.TYPE_USE)
public @interface ExternalPattern {

}
