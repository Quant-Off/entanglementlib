/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.Getter;
import space.qu4nt.entanglementlib.security.PostQuantumParameterSpec;

@Getter
public enum MLKEMType implements PostQuantumParameterSpec {

    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024;

    /**
     * ML-KEM 알고리즘은 그 배리언트를 공급자에 함께 전달해도 되지만,
     * {@link javax.crypto.KEM}갹체에 BC 공급자와 함께 사용하기 위해서는
     * {@code ML-KEM}을 전달해야 합니다.
     * <p>
     * 추 후 이 부분에 대한 JNI 업데이트 진행 시 변경을 연구해야 합니다.
     */
    private final String algorithmName = "ml-kem";

}
