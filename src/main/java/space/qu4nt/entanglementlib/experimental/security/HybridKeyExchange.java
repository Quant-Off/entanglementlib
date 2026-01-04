/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security;

import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.ApiStatus;
import space.qu4nt.entanglementlib.security.EntLibKey;

/**
 * 어떤 고전 암호와 PQC 알고리즘이든 조합하여 하이브리드 키 교환을 수행하는 범용 클래스입니다.
 * <p>
 * {@code exp-sless-strategy-alg} 브랜치에서 처음 시작됩니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Getter
@Setter
@SuppressWarnings("rawtypes")
@ApiStatus.Experimental
public final class HybridKeyExchange extends EntLibAlgorithm {

    public static final HybridKeyExchange X25519_MLKEM_768 = new HybridKeyExchange(
            "X25519MLKEM768",
            KeyExchange.X25519,
            KeyEncapsulate.ML_KEM_768
    );

//    public static final HybridKeyExchange X448_MLKEM_1024 = new HybridKeyExchange(
//            "X448-MLKEM-1024",
//            KeyExchange.X448,
//            KeyEncapsulate.ML_KEM_1024
//    );

    private String hybridName;
    private KeyExchange keyExchangeDetail;
    private KeyEncapsulate kemDetail;

    private HybridKeyExchange(String hybridName, KeyExchange keyExchangeDetail, KeyEncapsulate kemDetail) {
        //noinspection unchecked
        super(null, null, 0, false);
        this.hybridName = hybridName;
        this.keyExchangeDetail = keyExchangeDetail;
        this.kemDetail = kemDetail;
    }

    @Override
    public EntLibKey<?> keyGen() {
        throw new RuntimeException("cant keygen");
    }

}