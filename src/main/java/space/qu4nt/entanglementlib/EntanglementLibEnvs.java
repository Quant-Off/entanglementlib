/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib;

import com.quant.quantregular.annotations.QuantTypeOwner;
import com.quant.quantregular.annotations.Quanters;

/**
 * {@code EntanglementLib}에서 공통으로 사용되는 환경 변수 값을 정의한 클래스입니다.
 * <p>
 * 이 클래스는 {@link InternalFactory}에서만 구현되며, 외부에서 호출할 수 없습니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@QuantTypeOwner(Quanters.Q_T_FELIX)
sealed class EntanglementLibEnvs extends WrapEnv permits InternalFactory {

    private static final EntanglementLibEnvs entanglementPublicDir;

    private static final EntanglementLibEnvs entanglementHomeDir;


    static {
        entanglementPublicDir = new EntanglementLibEnvs("ENTANGLEMENT_PUBLIC_DIR"  , true);
        entanglementHomeDir   = new EntanglementLibEnvs("ENTANGLEMENT_HOME_DIR"    , true);
    }

    EntanglementLibEnvs() {
        throw new UnsupportedOperationException("do not empty instantiate this class");
    }

    EntanglementLibEnvs(String env, boolean req, String def) {
        super(env, req, def);
    }

    EntanglementLibEnvs(String env, boolean req) {
        this(env, req, null);
    }

    public static String envEntanglementPublicDir() {
        return entanglementPublicDir.getEnv();
    }

    public static String envEntanglementHomeDir() {
        return entanglementHomeDir.getEnv();
    }
}
