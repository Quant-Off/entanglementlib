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
import space.qu4nt.entanglementlib.experimental.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.experimental.crypto.SignatureType;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.detail.MLDSAStrategy;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.detail.SLHDSAStrategy;

/// SLH-DSA(Stateless Hash-based Digital Signature Algorithm) 스트레티지 번들 클래스입니다.
///
/// 모든 SLH-DSA 알고리즘 관련 스트레티지를 [EntLibCryptoRegistry]에 등록합니다.
/// SLH-DSA는 NIST에서 표준화한 PQC(Post-Quantum Cryptography) 전자 서명 알고리즘입니다.
///
/// @author Q. T. Felix
/// @see AbstractStrategyBundle
/// @see MLDSAStrategy
/// @since 1.1.0
public final class SLHDSAStrategyBundle extends AbstractStrategyBundle {

    /**
     * 싱글톤 인스턴스입니다.
     */
    private static final SLHDSAStrategyBundle INSTANCE = new SLHDSAStrategyBundle();

    /**
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    private SLHDSAStrategyBundle() {
    }

    /**
     * SLH-DSA 서명 스트레티지들을 레지스트리에 등록하는 메소드입니다.
     * <p>
     * SLH-DSA 번들 타입에 해당하는 스트레티지를 등록합니다.
     */
    @Override
    protected void registerStrategies() {
        register(SignatureType.SLH_DSA_SHA2_128s, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHA2_128s));
        register(SignatureType.SLH_DSA_SHA2_128f, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHA2_128f));
        register(SignatureType.SLH_DSA_SHA2_192s, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHA2_192s));
        register(SignatureType.SLH_DSA_SHA2_192f, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHA2_192f));
        register(SignatureType.SLH_DSA_SHA2_256s, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHA2_256s));
        register(SignatureType.SLH_DSA_SHA2_256f, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHA2_256f));
        register(SignatureType.SLH_DSA_SHAKE_128s, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHAKE_128s));
        register(SignatureType.SLH_DSA_SHAKE_128f, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHAKE_128f));
        register(SignatureType.SLH_DSA_SHAKE_192s, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHAKE_192s));
        register(SignatureType.SLH_DSA_SHAKE_192f, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHAKE_192f));
        register(SignatureType.SLH_DSA_SHAKE_256s, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHAKE_256s));

    }

    /**
     * 싱글톤 인스턴스를 반환하는 메소드입니다.
     *
     * @return {@link SLHDSAStrategyBundle} 싱글톤 인스턴스
     */
    public static SLHDSAStrategyBundle getInstance() {
        return INSTANCE;
    }

}
