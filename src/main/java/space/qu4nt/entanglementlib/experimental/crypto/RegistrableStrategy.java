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

package space.qu4nt.entanglementlib.experimental.crypto;

import space.qu4nt.entanglementlib.experimental.crypto.strategy.EntLibCryptoStrategy;

import java.util.Map;

/// 레지스트리에 등록 가능한 스트레티지를 위한 인터페이스입니다.
///
/// 암호화 스트레티지 또는 키 스트레티지 구현체가 이 인터페이스를 구현하면
/// [EntLibCryptoRegistry]에 자동으로 등록됩니다.
///
/// @author Q. T. Felix
/// @see AbstractStrategyBundle
/// @see EntLibCryptoRegistry
/// @since 1.1.0
public interface RegistrableStrategy {

    /**
     * 이 스트레티지 제공자가 등록할 스트레티지들을 반환하는 메소드입니다.
     *
     * @return 알고리즘 타입과 스트레티지의 매핑
     */
    Map<EntLibAlgorithmType, ? extends EntLibCryptoStrategy> getStrategies();

}
