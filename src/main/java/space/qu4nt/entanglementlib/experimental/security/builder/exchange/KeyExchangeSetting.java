/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security.builder.exchange;

import lombok.Builder;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.experimental.security.ECParameter;

@Builder
@ApiStatus.Experimental
public class KeyExchangeSetting {

    @Nullable
    private ECParameter ecParameter;
}
