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
public enum SLHDSAType implements PostQuantumParameterSpec {

    SLH_DSA_SHA2_128f,
    SLH_DSA_SHA2_128s,
    SLH_DSA_SHA2_192f,
    SLH_DSA_SHA2_192s,
    SLH_DSA_SHA2_256f,
    SLH_DSA_SHA2_256s,
    SLH_DSA_SHAKE_128f,
    SLH_DSA_SHAKE_128s,
    SLH_DSA_SHAKE_192f,
    SLH_DSA_SHAKE_192s,
    SLH_DSA_SHAKE_256f,
    SLH_DSA_SHAKE_256s,
    SLH_DSA_SHA2_128f_WITH_SHA256,
    SLH_DSA_SHA2_128s_WITH_SHA256,
    SLH_DSA_SHA2_192f_WITH_SHA512,
    SLH_DSA_SHA2_192s_WITH_SHA512,
    SLH_DSA_SHA2_256f_WITH_SHA512,
    SLH_DSA_SHA2_256s_WITH_SHA512,
    SLH_DSA_SHAKE_128f_WITH_SHAKE128,
    SLH_DSA_SHAKE_128s_WITH_SHAKE128,
    SLH_DSA_SHAKE_192f_WITH_SHAKE256,
    SLH_DSA_SHAKE_192s_WITH_SHAKE256,
    SLH_DSA_SHAKE_256f_WITH_SHAKE256,
    SLH_DSA_SHAKE_256s_WITH_SHAKE256;

    private final String algorithmName = toLowerCase(replace(name(), "_", "-"));

    public static Optional<SLHDSAType> fromName(final @NotNull String name) {
        return Arrays.stream(SLHDSAType.values())
                .filter(type -> name.trim().equalsIgnoreCase(type.getAlgorithmName()))
                .filter(type -> type.getAlgorithmName().length() == name.length())
                .findFirst();
    }
}
