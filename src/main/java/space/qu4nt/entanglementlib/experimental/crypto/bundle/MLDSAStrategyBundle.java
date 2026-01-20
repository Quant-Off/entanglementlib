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

/// ML-DSA(Module-Lattice Digital Signature Algorithm) 스트레티지 번들 클래스입니다.
///
/// ML-DSA-44, ML-DSA-65, ML-DSA-87 스트레티지를 [EntLibCryptoRegistry]에 등록합니다.
/// ML-DSA는 NIST에서 표준화한 PQC(Post-Quantum Cryptography) 전자 서명 알고리즘입니다.
///
/// @author Q. T. Felix
/// @see AbstractStrategyBundle
/// @see MLDSAStrategy
/// @since 1.1.0
public final class MLDSAStrategyBundle extends AbstractStrategyBundle {

    /**
     * 싱글톤 인스턴스입니다.
     */
    private static final MLDSAStrategyBundle INSTANCE = new MLDSAStrategyBundle();

    /**
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    private MLDSAStrategyBundle() {
    }

    /**
     * ML-DSA 서명 스트레티지들을 레지스트리에 등록하는 메소드입니다.
     * <p>
     * {@link SignatureType#ML_DSA_44}, {@link SignatureType#ML_DSA_65}, {@link SignatureType#ML_DSA_87}
     * 타입에 해당하는 스트레티지를 등록합니다.
     */
    @Override
    protected void registerStrategies() {
        register(SignatureType.ML_DSA_44, MLDSAStrategy.create(SignatureType.ML_DSA_44));
        register(SignatureType.ML_DSA_65, MLDSAStrategy.create(SignatureType.ML_DSA_65));
        register(SignatureType.ML_DSA_87, MLDSAStrategy.create(SignatureType.ML_DSA_87));
    }

    /**
     * 싱글톤 인스턴스를 반환하는 메소드입니다.
     *
     * @return {@link MLDSAStrategyBundle} 싱글톤 인스턴스
     */
    public static MLDSAStrategyBundle getInstance() {
        return INSTANCE;
    }

}
