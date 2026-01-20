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

package space.qu4nt.entanglementlib.experimental.crypto.strategy;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.security.algorithm.Digest;
import space.qu4nt.entanglementlib.security.algorithm.Mode;
import space.qu4nt.entanglementlib.security.algorithm.Padding;

/// 블록 암호화 전략 인터페이스입니다.
///
/// AES, ARIA 등의 블록 암호 알고리즘을 위한 전략을 정의합니다.
/// 운영 모드([Mode]), 패딩([Padding]), 다이제스트([Digest]) 설정을 지원합니다.
///
/// @author Q. T. Felix
/// @see CipherStrategy
/// @see Mode
/// @see Padding
/// @since 1.1.0
public interface BlockCipherStrategy extends CipherStrategy {

    /**
     * 현재 설정된 운영 모드를 반환하는 메소드입니다.
     *
     * @return 운영 모드 (CBC, GCM, CTR 등)
     */
    @NotNull Mode getMode();

    /**
     * 운영 모드를 설정하는 메소드입니다.
     *
     * @param mode 설정할 운영 모드
     * @return 메소드 체이닝을 위한 {@code this}
     */
    BlockCipherStrategy setMode(@NotNull Mode mode);

    /**
     * 현재 설정된 패딩을 반환하는 메소드입니다.
     *
     * @return 패딩 방식
     */
    @NotNull Padding getPadding();

    /**
     * 패딩을 설정하는 메소드입니다.
     *
     * @param padding 설정할 패딩 방식
     * @return 메소드 체이닝을 위한 {@code this}
     */
    BlockCipherStrategy setPadding(@NotNull Padding padding);

    /**
     * 현재 설정된 다이제스트를 반환하는 메소드입니다.
     *
     * @return 다이제스트, 설정되지 않은 경우 {@code null}
     */
    @Nullable Digest getDigest();

    /**
     * 다이제스트를 설정하는 메소드입니다.
     *
     * @param digest 설정할 다이제스트
     * @return 메소드 체이닝을 위한 {@code this}
     */
    BlockCipherStrategy setDigest(@NotNull Digest digest);

}
