/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security.builder.derivesetting;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.jetbrains.annotations.ApiStatus;
import space.qu4nt.entanglementlib.experimental.security.AlgorithmParameter;

/**
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Getter
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@ApiStatus.Experimental
public class KeyDerivationSettingResult {

    private AlgorithmParameter keyDeriveAlgorithm;
}
