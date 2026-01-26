/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.bundle;

import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import space.qu4nt.entanglementlib.security.crypto.AbstractStrategyBundle;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.SignatureType;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.SLHDSAKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.MLDSAStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.SLHDSAStrategy;

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
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    SLHDSAStrategyBundle() {
    }

    /**
     * SLH-DSA 서명 스트레티지들을 레지스트리에 등록하는 메소드입니다.
     * <p>
     * SLH-DSA 번들 타입에 해당하는 스트레티지를 등록합니다.
     */
    @Override
    protected void registerStrategies() {
        register(SignatureType.SLH_DSA_SHA2_128s, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHA2_128s), SLHDSAKeyStrategy.create(SLHDSAParameters.sha2_128s));
        register(SignatureType.SLH_DSA_SHA2_128f, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHA2_128f), SLHDSAKeyStrategy.create(SLHDSAParameters.sha2_128f));
        register(SignatureType.SLH_DSA_SHA2_192s, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHA2_192s), SLHDSAKeyStrategy.create(SLHDSAParameters.sha2_192s));
        register(SignatureType.SLH_DSA_SHA2_192f, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHA2_192f), SLHDSAKeyStrategy.create(SLHDSAParameters.sha2_192f));
        register(SignatureType.SLH_DSA_SHA2_256s, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHA2_256s), SLHDSAKeyStrategy.create(SLHDSAParameters.sha2_256s));
        register(SignatureType.SLH_DSA_SHA2_256f, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHA2_256f), SLHDSAKeyStrategy.create(SLHDSAParameters.sha2_256f));
        register(SignatureType.SLH_DSA_SHAKE_128s, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHAKE_128s), SLHDSAKeyStrategy.create(SLHDSAParameters.shake_128s));
        register(SignatureType.SLH_DSA_SHAKE_128f, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHAKE_128f), SLHDSAKeyStrategy.create(SLHDSAParameters.shake_128f));
        register(SignatureType.SLH_DSA_SHAKE_192s, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHAKE_192s), SLHDSAKeyStrategy.create(SLHDSAParameters.shake_192s));
        register(SignatureType.SLH_DSA_SHAKE_192f, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHAKE_192f), SLHDSAKeyStrategy.create(SLHDSAParameters.shake_192f));
        register(SignatureType.SLH_DSA_SHAKE_256s, SLHDSAStrategy.create(SignatureType.SLH_DSA_SHAKE_256s), SLHDSAKeyStrategy.create(SLHDSAParameters.shake_256s));
    }
}
