/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.bundle;

import org.jetbrains.annotations.ApiStatus;

@ApiStatus.Internal
public class BundleStaticCaller {

    /// 조만간 JPMS로 방어해야겠네
    @ApiStatus.Internal
    public static void call() {
        new AESStrategyBundle();
        new ARIAStrategyBundle();
        new ChaCha20StrategyBundle();
        new MLDSAStrategyBundle();
        new MLKEMStrategyBundle();
        new SLHDSAStrategyBundle();
        new X25519StrategyBundle();
        new X25519MLKEM768StrategyBundle();
    }
}
