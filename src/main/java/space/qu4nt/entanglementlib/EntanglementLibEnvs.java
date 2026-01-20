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

    private static final EntanglementLibEnvs entLibNativeDir;

    static {
        entanglementPublicDir = new EntanglementLibEnvs("ENTANGLEMENT_PUBLIC_DIR"  , true);
        entanglementHomeDir   = new EntanglementLibEnvs("ENTANGLEMENT_HOME_DIR"    , true);
        entLibNativeDir       = new EntanglementLibEnvs("ENTLIB_NATIVE_BIN"        , true);
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

    public static String envEntLibNativeDir() {
        return entLibNativeDir.getEnv();
    }
}
