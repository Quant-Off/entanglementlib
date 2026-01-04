/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security.builder.normalcipher;

import lombok.Builder;
import org.jetbrains.annotations.ApiStatus;

/**
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Builder
@ApiStatus.Experimental
public final class NormalCipherSetting {

    private byte[] iv;
}
