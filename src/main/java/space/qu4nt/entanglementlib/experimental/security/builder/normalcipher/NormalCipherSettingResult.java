/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security.builder.normalcipher;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;

@AllArgsConstructor(access = AccessLevel.PACKAGE)
@ApiStatus.Experimental
public final class NormalCipherSettingResult {
    private byte @Nullable [] iv;

    public byte @Nullable [] getIv() {
        return iv == null ? null : Arrays.copyOf(iv, iv.length);
    }
}
