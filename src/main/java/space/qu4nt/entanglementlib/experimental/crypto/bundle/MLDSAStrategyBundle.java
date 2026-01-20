/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.bundle;

import space.qu4nt.entanglementlib.experimental.crypto.AbstractStrategyBundle;
import space.qu4nt.entanglementlib.experimental.crypto.SignatureType;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.detail.MLDSAStrategy;

/**
 * ML-DSA(Module-Lattice Digital Signature Algorithm) 스트레티지 번들 클래스입니다.
 * <p>
 * ML-DSA-44, ML-DSA-65, ML-DSA-87 스트레티지를 {@link space.qu4nt.entanglementlib.experimental.crypto.EntLibCryptoRegistry}에 등록합니다.
 * ML-DSA는 NIST에서 표준화한 PQC(Post-Quantum Cryptography) 전자 서명 알고리즘입니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see AbstractStrategyBundle
 * @see MLDSAStrategy
 */
public final class MLDSAStrategyBundle extends AbstractStrategyBundle {

    /**
     * 싱글톤 인스턴스입니다.
     */
    private static final MLDSAStrategyBundle INSTANCE = new MLDSAStrategyBundle();

    /**
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    private MLDSAStrategyBundle() {}

    /**
     * ML-DSA 서명 스트레티지들을 레지스트리에 등록하는 메소드입니다.
     * <p>
     * {@link SignatureType#ML_DSA_44}, {@link SignatureType#ML_DSA_65}, {@link SignatureType#ML_DSA_87}
     * 타입에 해당하는 스트레티지를 등록합니다.
     * </p>
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
