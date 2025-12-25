/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.security.PostQuantumParameterSpec;

import java.util.Arrays;
import java.util.Optional;

import static space.qu4nt.entanglementlib.util.StringUtil.replace;
import static space.qu4nt.entanglementlib.util.StringUtil.toLowerCase;

@Getter
public enum MLDSAType implements PostQuantumParameterSpec {

    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
    ML_DSA_44_WITH_SHA512,
    ML_DSA_65_WITH_SHA512,
    ML_DSA_87_WITH_SHA512;

    private final String algorithmName = toLowerCase(replace(name(), "_", "-"));

    public static Optional<MLDSAType> fromName(final @NotNull String name) {
        return Arrays.stream(MLDSAType.values())
                .filter(type -> name.trim().equalsIgnoreCase(type.getAlgorithmName()))
                .filter(type -> type.getAlgorithmName().length() == name.length())
                .findFirst();
    }
}
