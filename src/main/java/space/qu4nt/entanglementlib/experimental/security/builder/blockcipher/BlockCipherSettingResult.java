/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security.builder.blockcipher;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.security.algorithm.Digest;
import space.qu4nt.entanglementlib.security.algorithm.Mode;
import space.qu4nt.entanglementlib.security.algorithm.Padding;

import java.util.Arrays;

@Getter
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@ApiStatus.Experimental
public final class BlockCipherSettingResult {
    private @NotNull Mode mode;
    private @NotNull Padding padding;
    private @Nullable Digest digest;
    private @NotNull String fullName;
    private byte @Nullable [] iv;

    public byte @Nullable [] getIv() {
        return iv == null ? null : Arrays.copyOf(iv, iv.length);
    }
}
