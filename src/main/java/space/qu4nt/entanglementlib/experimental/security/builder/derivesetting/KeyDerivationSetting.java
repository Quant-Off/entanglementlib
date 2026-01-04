/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security.builder.derivesetting;

import lombok.Builder;
import org.jetbrains.annotations.ApiStatus;
import space.qu4nt.entanglementlib.experimental.security.AlgorithmParameter;

/**
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Builder
@ApiStatus.Experimental
public class KeyDerivationSetting {

    private AlgorithmParameter keyDeriveAlgorithm;

    public KeyDerivationSetting keyDeriveAlgorithm(AlgorithmParameter keyDeriveAlgorithm) {
        this.keyDeriveAlgorithm = keyDeriveAlgorithm;
        return this;
    }

    public KeyDerivationSettingResult done() {
        return new KeyDerivationSettingResult(keyDeriveAlgorithm);
    }

    public static class KeyDerivationSettingBuilder {
        public KeyDerivationSettingResult done() {
            return build().done();
        }
    }
}
