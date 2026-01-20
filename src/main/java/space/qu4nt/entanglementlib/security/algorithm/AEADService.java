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

import org.jetbrains.annotations.Nullable;

/**
 * 알고리즘이 {@code AEAD(Authenticated Encryption with Associated Data)}를
 * 지원하도록 하는 인터페이스입니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
public interface AEADService {

    /**
     * AAD(Associated Data)를 반환하는 메소드입니다.
     * <p>
     * 내부적으로 복사본이 반환되어야 합니다.
     *
     * @return AAD(Associated Data) 바이트 배열, AAD가 할당되지 않은 경우 {@code null}
     */
    @Deprecated
    default byte @Nullable [] getAAD() {return new byte[1];}
}
