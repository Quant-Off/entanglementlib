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

package space.qu4nt.entanglementlib.experimental.crypto.bundle;

import space.qu4nt.entanglementlib.experimental.crypto.AbstractStrategyBundle;
import space.qu4nt.entanglementlib.experimental.crypto.CipherType;
import space.qu4nt.entanglementlib.experimental.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.detail.AESStrategy;

/// AES 알고리즘 스트레티지 번들 클래스입니다.
///
/// AES-128, AES-192, AES-256 스트레티지를 [EntLibCryptoRegistry]에 등록합니다.
///
/// @author Q. T. Felix
/// @see AbstractStrategyBundle
/// @see AESStrategy
/// @since 1.1.0
public final class AESStrategyBundle extends AbstractStrategyBundle {

    /**
     * 싱글톤 인스턴스입니다.
     */
    private static final AESStrategyBundle INSTANCE = new AESStrategyBundle();

    /**
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    private AESStrategyBundle() {
    }

    /**
     * AES 암호화 스트레티지들을 레지스트리에 등록하는 메소드입니다.
     * <p>
     * {@link CipherType#AES_128}, {@link CipherType#AES_192}, {@link CipherType#AES_256}
     * 타입에 해당하는 스트레티지를 등록합니다.
     */
    @Override
    protected void registerStrategies() {
        register(CipherType.AES_128, AESStrategy.create(CipherType.AES_128));
        register(CipherType.AES_192, AESStrategy.create(CipherType.AES_192));
        register(CipherType.AES_256, AESStrategy.create(CipherType.AES_256));
    }

    /**
     * 싱글톤 인스턴스를 반환하는 메소드입니다.
     *
     * @return {@link AESStrategyBundle} 싱글톤 인스턴스
     */
    public static AESStrategyBundle getInstance() {
        return INSTANCE;
    }

}
