/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security;

import org.jetbrains.annotations.NotNull;

import java.util.Objects;

public interface PostQuantumParameterSpec extends EntLibParameterSpec {

    @Override
    default boolean startsWith(@NotNull String prefix) {
        return Objects.requireNonNull(getAlgorithmName(), "pqc algorithm name").startsWith(prefix);
    }

}
